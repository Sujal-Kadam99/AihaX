"""SQLAlchemy database setup, ORM models, and connection management."""

import functools
import logging
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional, Generator, Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    text,
)
from sqlalchemy.pool import StaticPool
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker
from sqlalchemy.types import TypeDecorator

from backend.core.config import get_settings
from backend.core.encrypted_type import EncryptedText
from backend.models.migrations import run_migrations

logger = logging.getLogger(__name__)


class UTCDateTime(TypeDecorator):
    """SQLAlchemy TypeDecorator that guarantees timezone-aware UTC datetime round-trips."""

    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            else:
                value = value.astimezone(timezone.utc)
            return value.isoformat()
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, str):
            dt = datetime.fromisoformat(value)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return value


from enum import Enum


def get_utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class FindingDisposition(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    PREREQUISITE_MISSING = "PREREQUISITE_MISSING"
    BLOCKED_AUTHORIZATION = "BLOCKED_AUTHORIZATION"
    BLOCKED_SCOPE = "BLOCKED_SCOPE"
    BLOCKED_SAFETY = "BLOCKED_SAFETY"
    BLOCKED_BUDGET = "BLOCKED_BUDGET"
    DETECTED = "DETECTED"
    VALIDATED = "VALIDATED"
    EXPLOITABLE = "EXPLOITABLE"
    TESTED_NO_FINDING = "TESTED_NO_FINDING"
    INCONCLUSIVE = "INCONCLUSIVE"
    HARDENING_ONLY = "HARDENING_ONLY"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_HUMAN_REVIEW = "NEEDS_HUMAN_REVIEW"
    NOT_BOUNTY_ELIGIBLE = "NOT_BOUNTY_ELIGIBLE"
    VERIFICATION_ERROR = "VERIFICATION_ERROR"
    # Legacy alias
    VULNERABILITY = "VULNERABILITY"


class BountyEligibility(str, Enum):
    ELIGIBLE = "ELIGIBLE"
    INELIGIBLE = "INELIGIBLE"
    UNKNOWN = "UNKNOWN"


class Base(DeclarativeBase):
    pass


class Program(Base):
    __tablename__ = "programs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False, index=True)
    description = Column(Text, nullable=True)
    user_id = Column(String, nullable=True, index=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    # Phase 16: Bug-bounty program metadata
    platform = Column(String, nullable=True)  # e.g. "hackerone", "bugcrowd", "internal"
    policy_url = Column(String, nullable=True)
    policy_version = Column(String, nullable=True)
    policy_updated_at = Column(UTCDateTime, nullable=True)
    bounty_eligible = Column(Boolean, nullable=False, default=False)

    # ORM Relationships
    scope = relationship("ProgramScope", back_populates="program", uselist=False, cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="program")
    assets = relationship("Asset", back_populates="program", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="program", cascade="all, delete-orphan")
    scope_assets = relationship("BugBountyScopeAsset", back_populates="program", cascade="all, delete-orphan")


class ProgramScope(Base):
    __tablename__ = "program_scopes"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    program_id = Column(String, ForeignKey("programs.id"), unique=True, nullable=False, index=True)
    in_scope_assets = Column(Text, nullable=False, default="[]")
    out_of_scope_assets = Column(Text, nullable=False, default="[]")
    allowed_ports = Column(Text, nullable=True, default="[]")
    excluded_ports = Column(Text, nullable=True, default="[]")
    allowed_schemes = Column(Text, nullable=True, default='["http", "https"]')
    excluded_paths = Column(Text, nullable=True, default="[]")
    scope_notes = Column(Text, nullable=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)
    updated_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    # ORM Relationships
    program = relationship("Program", back_populates="scope")


class BugBountyScopeAsset(Base):
    """Phase 16: Per-asset structured scope definition for bug-bounty programs.

    Represents a single scope entry from a bug-bounty program (e.g. *.xiaomi.com).
    Wildcard scope assets define what IS in scope but are NOT executable targets.
    A concrete target must be independently supplied and validated against these definitions.
    """
    __tablename__ = "bug_bounty_scope_assets"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    program_id = Column(String, ForeignKey("programs.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_name = Column(String, nullable=False)  # Human-readable label
    asset_type = Column(String, nullable=False, default="DOMAIN")  # DOMAIN, SUBDOMAIN, URL, IP, CIDR, WILDCARD, ANDROID_APK, IOS_APP, HARDWARE, OTHER
    scope_type = Column(String, nullable=False, default="IN_SCOPE")  # IN_SCOPE, OUT_OF_SCOPE
    severity = Column(String, nullable=True)  # e.g. "critical", "high", "medium", "low"
    bounty_eligible = Column(Boolean, nullable=False, default=False)
    raw_scope_definition = Column(Text, nullable=False)  # Original as-imported definition (e.g. "*.xiaomi.com")
    normalized_scope_definition = Column(Text, nullable=False)  # Deterministically normalized form
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("program_id", "raw_scope_definition", "scope_type", name="uq_scope_asset_program_def_type"),
    )

    # ORM Relationships
    program = relationship("Program", back_populates="scope_assets")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target_url = Column(String, nullable=False)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False, index=True)
    completed_at = Column(UTCDateTime, nullable=True)
    status = Column(String, nullable=False, default="pending", index=True)
    scan_depth = Column(String, nullable=False, default="normal")
    scan_mode = Column(String, nullable=False, default="safe")
    threads = Column(Integer, nullable=False, default=5)
    waf_bypass = Column(Boolean, nullable=False, default=False)
    stealth_mode = Column(Boolean, nullable=False, default=False)
    industry = Column(String, nullable=True)
    tech_stack = Column(Text, nullable=True)
    total_findings = Column(Integer, default=0)
    risk_score = Column(Integer, nullable=True)
    report_path = Column(String, nullable=True)
    report_format = Column(String, nullable=False, default="full")
    schedule_id = Column(String, ForeignKey("watch_schedules.id"), nullable=True)
    admin_mode = Column(Boolean, nullable=False, default=False)
    program_id = Column(String, ForeignKey("programs.id"), nullable=True, index=True)
    rate_limit_rps = Column(Integer, nullable=False, default=10)
    max_concurrency = Column(Integer, nullable=False, default=5)

    # User tracking for per-user limits / freemium
    user_id = Column(String, nullable=True, index=True)
    user_email = Column(String, nullable=True, index=True)

    # ORM Relationships
    program = relationship("Program", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    agent_logs = relationship("AgentLog", back_populates="scan", cascade="all, delete-orphan")
    exploit_chains = relationship("ExploitChain", back_populates="scan", cascade="all, delete-orphan")
    scan_config = relationship("ScanConfig", back_populates="scan", uselist=False, cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)
    agent_id = Column(Integer, nullable=False)
    title = Column(String, nullable=False)
    vuln_type = Column(String, nullable=False, index=True)
    category = Column(String, nullable=False)
    severity = Column(String, nullable=False, index=True)
    cvss_score = Column(Float, nullable=True)
    cwe_id = Column(String, nullable=True)
    cve_id = Column(String, nullable=True)
    affected_url = Column(String, nullable=False)
    affected_param = Column(String, nullable=True)
    payload = Column(Text, nullable=True)
    proof_request = Column(Text, nullable=True)
    proof_response = Column(Text, nullable=True)
    screenshot_path = Column(String, nullable=True)
    confidence = Column(Integer, nullable=False, default=0)
    false_positive = Column(Boolean, default=False)
    verdict = Column(String, default="Inconclusive", nullable=False)
    verification_status = Column(String, default="CANDIDATE", nullable=False, index=True)
    verification_reason_code = Column(String, nullable=True)
    verification_method = Column(String, nullable=True)
    verification_timestamp = Column(UTCDateTime, nullable=True)
    evidence_ids = Column(Text, default="[]", nullable=False)
    request_ids = Column(Text, default="[]", nullable=False)
    remediation = Column(Text, nullable=True)
    business_impact = Column(Text, nullable=True)
    chain_id = Column(String, nullable=True)
    confidence_reason = Column(String, nullable=True)
    verifier_version = Column(String, nullable=True)
    impact_record = Column(Text, nullable=True)
    evidence_hashes = Column(Text, default="{}", nullable=False)
    human_review_status = Column(String, default="PENDING", nullable=False, index=True)
    human_reviewed_by = Column(String, nullable=True)
    human_reviewed_at = Column(UTCDateTime, nullable=True)
    human_review_notes = Column(Text, nullable=True)
    duplicate_of = Column(String, nullable=True, index=True)
    deduplication_reason = Column(String, nullable=True)
    finding_fingerprint = Column(String, nullable=True, index=True)
    quality_score = Column(Float, nullable=True)
    quality_band = Column(String, nullable=True)
    impact_confirmed = Column(Text, nullable=True)
    impact_potential = Column(Text, nullable=True)
    # Finding Quality & False-Positive Validation Gate
    finding_disposition = Column(String, default="INCONCLUSIVE", nullable=False, index=True)
    condition_confidence = Column(Float, default=0.0, nullable=False)
    impact_confidence = Column(Float, default=0.0, nullable=False)
    reproducibility_confidence = Column(Float, default=0.0, nullable=False)
    exploitability_confidence = Column(Float, default=0.0, nullable=False)
    bounty_eligibility = Column(String, default="UNKNOWN", nullable=False, index=True)
    policy_eligibility_confidence = Column(Float, default=0.0, nullable=False)
    verification_explanation = Column(Text, nullable=True)
    parent_finding_id = Column(String, nullable=True, index=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    # ORM Relationships
    scan = relationship("Scan", back_populates="findings")


class AgentLog(Base):
    __tablename__ = "agent_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)
    agent_id = Column(Integer, nullable=False)
    level = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    raw_output = Column(Text, nullable=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    # ORM Relationships
    scan = relationship("Scan", back_populates="agent_logs")


class ExploitChain(Base):
    __tablename__ = "exploit_chains"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)
    chain_name = Column(String, nullable=False)
    severity_final = Column(String, nullable=False)
    steps = Column(Text, nullable=False)
    impact_summary = Column(Text, nullable=True)
    diagram_path = Column(String, nullable=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    # ORM Relationships
    scan = relationship("Scan", back_populates="exploit_chains")


class ScanConfig(Base):
    __tablename__ = "scan_configs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)
    program_id = Column(String, nullable=True)
    rate_limit_rps = Column(Integer, nullable=False, default=10)
    max_concurrency = Column(Integer, nullable=False, default=5)
    # Encrypted fields at rest
    primary_creds = Column(EncryptedText, nullable=True)
    secondary_creds = Column(EncryptedText, nullable=True)
    email_creds = Column(EncryptedText, nullable=True)
    two_fa_type = Column(String, nullable=True)
    two_fa_config = Column(EncryptedText, nullable=True)
    api_auth = Column(EncryptedText, nullable=True)
    authorization_confirmed = Column(Boolean, nullable=False, default=False)
    authorization_notes = Column(Text, nullable=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    # ORM Relationships
    scan = relationship("Scan", back_populates="scan_config")


class WatchSchedule(Base):
    __tablename__ = "watch_schedules"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target_url = Column(String, nullable=False)
    schedule_type = Column(String, nullable=False)
    last_run = Column(UTCDateTime, nullable=True)
    next_run = Column(UTCDateTime, nullable=True, index=True)
    base_scan_id = Column(String, nullable=True)
    last_scan_id = Column(String, nullable=True)
    watch_name = Column(String, nullable=True)
    scan_payload = Column(Text, nullable=True)
    scope_notes = Column(Text, nullable=True)
    alert_webhook = Column(String, nullable=True)
    alert_email = Column(String, nullable=True)
    delta_summary = Column(Text, nullable=True)
    active = Column(Boolean, default=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, nullable=False)
    plan_name = Column(String, nullable=False)
    status = Column(String, nullable=False, default="active")
    start_date = Column(UTCDateTime, default=get_utc_now, nullable=False)
    end_date = Column(UTCDateTime, nullable=False)
    last_notified = Column(UTCDateTime, nullable=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)
    stripe_subscription_id = Column(String, nullable=True)
    stripe_customer_id = Column(String, nullable=True)
    stripe_checkout_session_id = Column(String, nullable=True)


class StripeWebhookEvent(Base):
    """Processed Stripe event IDs provide webhook retry idempotency."""

    __tablename__ = "stripe_webhook_events"

    event_id = Column(String, primary_key=True)
    event_type = Column(String, nullable=False)
    received_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    google_sub = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    email_verified = Column(Boolean, default=False, nullable=False)
    name = Column(String, nullable=True)
    picture = Column(String, nullable=True)
    account_status = Column(String, default="active", nullable=False)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)
    last_login_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    # ORM Relationships
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    organization_memberships = relationship(
        "OrganizationMember",
        back_populates="user",
        foreign_keys="OrganizationMember.user_id",
        cascade="all, delete-orphan",
    )


class Organization(Base):
    """A paid workspace that owns shared campaign access and membership."""

    __tablename__ = "organizations"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(120), nullable=False)
    created_by_user_id = Column(String, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    creator = relationship("User", foreign_keys=[created_by_user_id])
    members = relationship("OrganizationMember", back_populates="organization", cascade="all, delete-orphan")
    campaigns = relationship("Campaign", back_populates="organization")


class OrganizationMember(Base):
    """An active user and role assignment inside an organization."""

    __tablename__ = "organization_members"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_organization_member_user"),
        CheckConstraint("role IN ('owner', 'admin', 'member', 'viewer')", name="ck_organization_member_role"),
    )

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(16), nullable=False, default="member")
    invited_by_user_id = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    organization = relationship("Organization", back_populates="members")
    user = relationship("User", foreign_keys=[user_id], back_populates="organization_memberships")
    invited_by = relationship("User", foreign_keys=[invited_by_user_id])


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String, unique=True, index=True, nullable=False)
    family_id = Column(String, nullable=False, index=True)
    revoked = Column(Boolean, default=False, nullable=False)
    expires_at = Column(UTCDateTime, nullable=False)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    # ORM Relationships
    user = relationship("User", back_populates="refresh_tokens")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    entity_type = Column(String, nullable=False, index=True)
    entity_id = Column(String, nullable=False, index=True)
    action = Column(String, nullable=False, index=True)
    old_value = Column(String, nullable=True)
    new_value = Column(String, nullable=True)
    user_id = Column(String, nullable=True, index=True)
    metadata_json = Column(Text, nullable=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False, index=True)


class EntitlementCache(Base):
    __tablename__ = "entitlement_cache"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, unique=True, index=True, nullable=False)
    plan_name = Column(String, nullable=False)
    entitlement_jwt = Column(Text, nullable=False)
    features_json = Column(Text, nullable=True)
    synced_at = Column(UTCDateTime, default=get_utc_now, nullable=False)
    expires_at = Column(UTCDateTime, nullable=False, index=True)


class DiscoverySource(Base):
    __tablename__ = "discovery_sources"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    source_code = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    # ORM Relationships
    observations = relationship("AssetObservation", back_populates="source")
    endpoints = relationship("Endpoint", back_populates="source")
    technologies = relationship("TechnologyFingerprint", back_populates="source")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    program_id = Column(String, ForeignKey("programs.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_type = Column(String, nullable=False, index=True)  # DOMAIN, SUBDOMAIN, IP_ADDRESS, CIDR, URL
    normalized_value = Column(String, nullable=False, index=True)
    scope_status = Column(String, nullable=False, default="UNKNOWN", index=True)  # UNKNOWN, IN_SCOPE, OUT_OF_SCOPE, DISCOVERED
    active_testing_allowed = Column(Boolean, nullable=False, default=False, index=True)
    authorization_confirmed = Column(Boolean, nullable=False, default=False, index=True)
    dns_records = Column(Text, nullable=True)  # JSON string of DNS records
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)
    updated_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("program_id", "asset_type", "normalized_value", name="uq_assets_program_type_value"),
    )

    # ORM Relationships
    program = relationship("Program", back_populates="assets")
    observations = relationship("AssetObservation", back_populates="asset", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="asset", cascade="all, delete-orphan")
    technologies = relationship("TechnologyFingerprint", back_populates="asset", cascade="all, delete-orphan")


class AssetObservation(Base):
    __tablename__ = "asset_observations"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id = Column(String, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    source_id = Column(String, ForeignKey("discovery_sources.id"), nullable=False, index=True)
    request_id = Column(String, nullable=True, index=True)
    evidence_id = Column(String, nullable=True, index=True)
    raw_data = Column(Text, nullable=True)
    confidence = Column(Integer, nullable=False, default=0)
    observed_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    # ORM Relationships
    asset = relationship("Asset", back_populates="observations")
    source = relationship("DiscoverySource", back_populates="observations")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    program_id = Column(String, ForeignKey("programs.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    normalized_url = Column(String, nullable=False, index=True)
    path = Column(String, nullable=False)
    query_parameters = Column(Text, nullable=True)  # JSON string of parameters
    source_id = Column(String, ForeignKey("discovery_sources.id"), nullable=True, index=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("asset_id", "normalized_url", name="uq_endpoints_asset_url"),
    )

    # ORM Relationships
    program = relationship("Program", back_populates="endpoints")
    asset = relationship("Asset", back_populates="endpoints")
    source = relationship("DiscoverySource", back_populates="endpoints")


class TechnologyFingerprint(Base):
    __tablename__ = "technology_fingerprints"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id = Column(String, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    technology = Column(String, nullable=False, index=True)
    version = Column(String, nullable=True)
    detection_rule = Column(String, nullable=True)
    source_id = Column(String, ForeignKey("discovery_sources.id"), nullable=True, index=True)
    confidence = Column(Integer, nullable=False, default=0)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    # ORM Relationships
    asset = relationship("Asset", back_populates="technologies")
    source = relationship("DiscoverySource", back_populates="technologies")


# Phase 20: Hunting Intelligence & Learning Entities
class CheckEffectivenessRecord(Base):
    __tablename__ = "check_effectiveness"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    check_id = Column(String, nullable=False, unique=True, index=True)
    executions = Column(Integer, default=0, nullable=False)
    candidates = Column(Integer, default=0, nullable=False)
    verified = Column(Integer, default=0, nullable=False)
    rejected = Column(Integer, default=0, nullable=False)
    inconclusive = Column(Integer, default=0, nullable=False)
    duplicates = Column(Integer, default=0, nullable=False)
    evidence_complete = Column(Integer, default=0, nullable=False)
    evidence_incomplete = Column(Integer, default=0, nullable=False)
    total_requests = Column(Integer, default=0, nullable=False)
    average_requests = Column(Float, default=0.0, nullable=False)
    verification_rate = Column(Float, default=0.0, nullable=False)
    evidence_quality = Column(Float, default=0.0, nullable=False)
    uniqueness = Column(Float, default=0.0, nullable=False)
    impact_signal = Column(Float, default=0.0, nullable=False)
    utility = Column(Float, default=0.0, nullable=False, index=True)
    updated_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class NegativeEvidenceRecord(Base):
    __tablename__ = "negative_evidence"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target = Column(String, nullable=False, index=True)
    endpoint = Column(String, nullable=False, index=True)
    check_id = Column(String, nullable=False, index=True)
    timestamp = Column(UTCDateTime, default=get_utc_now, nullable=False)
    request_hash = Column(String, nullable=False)
    response_hash = Column(String, nullable=False)
    verdict = Column(String, nullable=False)
    verification_state = Column(String, nullable=False)
    scope_snapshot_hash = Column(String, nullable=True)
    verifier_version = Column(String, nullable=True)
    details = Column(Text, nullable=True)


class SurfaceInventoryRecord(Base):
    __tablename__ = "surface_inventory"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target = Column(String, nullable=False, index=True)
    endpoint = Column(String, nullable=False, index=True)
    http_method = Column(String, nullable=False)
    normalized_path = Column(String, nullable=False, index=True)
    parameters = Column(Text, default="[]", nullable=False)
    content_type = Column(String, nullable=True)
    auth_state = Column(String, default="ANONYMOUS", nullable=False)
    status_code = Column(Integer, nullable=True)
    interesting_headers = Column(Text, default="{}", nullable=False)
    observed_findings = Column(Text, default="[]", nullable=False)
    negative_evidence = Column(Text, default="[]", nullable=False)
    discovered_at = Column(UTCDateTime, default=get_utc_now, nullable=False)
    updated_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class AssessmentMemoryRecord(Base):
    __tablename__ = "assessment_memory"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, nullable=True)
    target = Column(String, nullable=False, index=True)
    lesson_type = Column(String, nullable=False, index=True)
    key = Column(String, nullable=False)
    value = Column(Text, nullable=False)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class OperatorDecisionRecord(Base):
    __tablename__ = "operator_decisions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    recommendation_id = Column(String, nullable=False)
    campaign_id = Column(String, nullable=False, index=True)
    target = Column(String, nullable=False)
    check_id = Column(String, nullable=False, index=True)
    operator_id = Column(String, nullable=False)
    decision = Column(String, nullable=False)  # APPROVE, REJECT, SKIP, ALREADY_TESTED, REQUEST_REVERIFICATION
    timestamp = Column(UTCDateTime, default=get_utc_now, nullable=False)
    reason = Column(Text, nullable=True)
    remaining_budget = Column(Integer, nullable=False)
    plan_hash = Column(String, nullable=True)
    audit_hash = Column(String, nullable=False, index=True)


class HuntingRecommendationRecord(Base):
    __tablename__ = "hunting_recommendations"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, nullable=False, index=True)
    target = Column(String, nullable=False)
    check_id = Column(String, nullable=False, index=True)
    reason = Column(Text, nullable=False)
    expected_evidence = Column(Text, nullable=False)
    estimated_requests = Column(Integer, nullable=False)
    risk_level = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    supporting_historical_evidence = Column(Text, nullable=True)
    authorization_status = Column(String, default="HUMAN_REVIEW_REQUIRED", nullable=False)
    status = Column(String, default="PENDING", nullable=False, index=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


# ==============================================================================
# Phase 21: Controlled Vulnerability Validation & Evidence-First Discovery Models
# ==============================================================================

class VulnerabilityHypothesisRecord(Base):
    __tablename__ = "vulnerability_hypotheses"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, nullable=False, index=True)
    target = Column(String, nullable=False, index=True)
    endpoint = Column(String, nullable=False, index=True)
    method = Column(String, nullable=False, default="GET")
    parameter = Column(String, nullable=True)
    vulnerability_class = Column(String, nullable=False, index=True)
    hypothesis = Column(Text, nullable=False)
    rationale = Column(Text, nullable=False)
    prerequisite_observations = Column(Text, nullable=False, default="[]")
    expected_evidence = Column(Text, nullable=False)
    verification_strategy = Column(Text, nullable=False)
    estimated_requests = Column(Integer, nullable=False, default=1)
    risk_level = Column(String, nullable=False, default="SAFE_ACTIVE")
    confidence = Column(Float, nullable=False, default=0.5)
    authorization_status = Column(String, default="HUMAN_REVIEW_REQUIRED", nullable=False)
    source_observations = Column(Text, nullable=True, default="[]")
    status = Column(String, default="PENDING", nullable=False, index=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)
    engine_version = Column(String, default="1.0.0-phase21", nullable=False)

    @property
    def hypothesis_id(self) -> str:
        return self.id

    @property
    def strategy_id(self) -> str:
        return self.verification_strategy

    @property
    def vuln_type(self) -> str:
        return self.vulnerability_class


class VerificationStrategyRecord(Base):
    __tablename__ = "verification_strategies"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    strategy_id = Column(String, nullable=False, unique=True, index=True)
    vulnerability_class = Column(String, nullable=False, index=True)
    prerequisite_evidence = Column(Text, nullable=False, default="[]")
    request_budget = Column(Integer, nullable=False, default=1)
    allowed_methods = Column(Text, nullable=False, default="[\"GET\", \"HEAD\", \"OPTIONS\"]")
    expected_observations = Column(Text, nullable=False, default="[]")
    success_conditions = Column(Text, nullable=False, default="[]")
    failure_conditions = Column(Text, nullable=False, default="[]")
    inconclusive_conditions = Column(Text, nullable=False, default="[]")
    safety_constraints = Column(Text, nullable=False, default="[]")
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class VerificationRunRecord(Base):
    __tablename__ = "verification_runs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, nullable=False, index=True)
    hypothesis_id = Column(String, nullable=False, index=True)
    strategy_id = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False, index=True)  # CONFIRMED, NOT_CONFIRMED, INCONCLUSIVE, BLOCKED_SCOPE, BLOCKED_SAFETY, BLOCKED_BUDGET, BLOCKED_AUTHORIZATION, BLOCKED_METHOD
    requests_consumed = Column(Integer, nullable=False, default=0)
    started_at = Column(UTCDateTime, default=get_utc_now, nullable=False)
    completed_at = Column(UTCDateTime, nullable=True)
    result_details = Column(Text, nullable=True)
    finding_id = Column(String, nullable=True, index=True)


class VerificationEvidenceRecord(Base):
    __tablename__ = "verification_evidence"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    verification_run_id = Column(String, nullable=False, index=True)
    campaign_id = Column(String, nullable=False, index=True)
    hypothesis_id = Column(String, nullable=False, index=True)
    strategy_id = Column(String, nullable=False)
    target = Column(String, nullable=False, index=True)
    endpoint = Column(String, nullable=False, index=True)
    method = Column(String, nullable=False)
    request_hash = Column(String, nullable=False)
    response_hash = Column(String, nullable=False)
    status_code = Column(Integer, nullable=True)
    response_size = Column(Integer, nullable=True)
    timestamp = Column(UTCDateTime, default=get_utc_now, nullable=False)
    scope_snapshot_hash = Column(String, nullable=True)
    verifier_version = Column(String, default="1.0.0-phase21", nullable=False)
    authorization_decision = Column(String, default="APPROVE", nullable=False)
    relevant_headers = Column(Text, nullable=True, default="{}")
    sanitized_request = Column(Text, nullable=True)
    sanitized_response = Column(Text, nullable=True)
    comparison_hash = Column(String, nullable=True)
    authentication_context_id = Column(String, nullable=True)
    baseline_evidence_id = Column(String, nullable=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class VerificationBudgetEntryRecord(Base):
    __tablename__ = "verification_budget_entries"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, nullable=False, index=True)
    verification_run_id = Column(String, nullable=False, index=True)
    request_number = Column(Integer, nullable=False)
    request_cost = Column(Integer, nullable=False, default=1)
    remaining_budget = Column(Integer, nullable=False)
    strategy_id = Column(String, nullable=False)
    operator_decision_id = Column(String, nullable=False, index=True)
    timestamp = Column(UTCDateTime, default=get_utc_now, nullable=False)


class HypothesisDecisionRecord(Base):
    __tablename__ = "hypothesis_decisions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    decision_id = Column(String, nullable=False, unique=True, index=True)
    operator_id = Column(String, nullable=False)
    campaign_id = Column(String, nullable=False, index=True)
    hypothesis_id = Column(String, nullable=False, index=True)
    strategy_id = Column(String, nullable=False)
    decision = Column(String, nullable=False)  # APPROVE, REJECT, SKIP, ALREADY_TESTED, REQUEST_REVERIFICATION
    rationale = Column(Text, nullable=True)
    timestamp = Column(UTCDateTime, default=get_utc_now, nullable=False)
    previous_hash = Column(String, nullable=False)
    event_hash = Column(String, nullable=False, index=True)


class RealVerificationRunRecord(Base):
    __tablename__ = "real_verification_runs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, nullable=False, index=True)
    hypothesis_id = Column(String, nullable=False, index=True)
    strategy_id = Column(String, nullable=False, index=True)
    target = Column(String, nullable=False)
    execution_mode = Column(String, nullable=False, default="PRODUCTION")  # PRODUCTION or TEST
    status = Column(String, nullable=False, index=True)  # PENDING, RUNNING, CONFIRMED, NOT_CONFIRMED, INCONCLUSIVE, CONTRADICTED, BLOCKED_SCOPE, BLOCKED_SAFETY, BLOCKED_BUDGET, BLOCKED_AUTHORIZATION, BLOCKED_METHOD, FAILED_TRANSPORT
    authorization_status = Column(String, nullable=False, default="HUMAN_REVIEW_REQUIRED")
    operator_approval_id = Column(String, nullable=True)
    requests_consumed = Column(Integer, nullable=False, default=0)
    started_at = Column(UTCDateTime, default=get_utc_now, nullable=False)
    completed_at = Column(UTCDateTime, nullable=True)
    result_details = Column(Text, nullable=True)
    correlation_verdict = Column(String, nullable=True)
    impact_summary = Column(Text, nullable=True)
    finding_id = Column(String, nullable=True, index=True)
    error_code = Column(String, nullable=True)
    executor_version = Column(String, nullable=False, default="1.0.0-phase22")
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class RealVerificationEvidenceRecord(Base):
    __tablename__ = "real_verification_evidence"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    verification_run_id = Column(String, nullable=False, index=True)
    campaign_id = Column(String, nullable=False, index=True)
    hypothesis_id = Column(String, nullable=False, index=True)
    target = Column(String, nullable=False, index=True)
    endpoint = Column(String, nullable=False, index=True)
    method = Column(String, nullable=False)
    request_hash = Column(String, nullable=False)
    response_hash = Column(String, nullable=False)
    status_code = Column(Integer, nullable=True)
    response_size = Column(Integer, nullable=True)
    timestamp = Column(UTCDateTime, default=get_utc_now, nullable=False)
    scope_snapshot_hash = Column(String, nullable=True)
    verifier_version = Column(String, default="1.0.0-phase22", nullable=False)
    authorization_decision = Column(String, default="APPROVE", nullable=False)
    sanitized_request = Column(Text, nullable=True)
    sanitized_response = Column(Text, nullable=True)
    relevant_headers = Column(Text, nullable=True, default="{}")
    baseline_evidence_id = Column(String, nullable=True)
    comparison_hash = Column(String, nullable=True)
    chain_hash = Column(String, nullable=True)
    authentication_context_id = Column(String, nullable=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class RealExploitEventRecord(Base):
    __tablename__ = "real_exploit_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, nullable=False, index=True)
    verification_run_id = Column(String, nullable=False, index=True)
    event_type = Column(String, nullable=False, index=True)
    event_details = Column(Text, nullable=True)
    operator_id = Column(String, nullable=False)
    timestamp = Column(UTCDateTime, default=get_utc_now, nullable=False)
    previous_hash = Column(String, nullable=False)
    event_hash = Column(String, nullable=False, index=True)


class RealOperatorApprovalRecord(Base):
    __tablename__ = "real_operator_approvals"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    approval_id = Column(String, nullable=False, unique=True, index=True)
    campaign_id = Column(String, nullable=False, index=True)
    hypothesis_id = Column(String, nullable=False, index=True)
    strategy_id = Column(String, nullable=False)
    operator_id = Column(String, nullable=False)
    target = Column(String, nullable=False)
    decision = Column(String, nullable=False)  # APPROVE, REJECT, SKIP, ALREADY_TESTED, REQUEST_REVERIFICATION
    acknowledgement = Column(Text, nullable=True)
    rationale = Column(Text, nullable=True)
    timestamp = Column(UTCDateTime, default=get_utc_now, nullable=False)
    previous_hash = Column(String, nullable=False)
    event_hash = Column(String, nullable=False, index=True)


class RealEvidenceChainRecord(Base):
    __tablename__ = "real_evidence_chains"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, nullable=False, index=True)
    verification_run_id = Column(String, nullable=False, index=True)
    baseline_hash = Column(String, nullable=False)
    verification_hash = Column(String, nullable=False)
    comparison_hash = Column(String, nullable=False)
    correlation_hash = Column(String, nullable=False)
    chain_hash = Column(String, nullable=False, index=True)
    previous_chain_hash = Column(String, nullable=False)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class RealImpactAssessmentRecord(Base):
    __tablename__ = "real_impact_assessments"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    verification_run_id = Column(String, nullable=False, index=True)
    confirmed_impact = Column(Text, nullable=False)
    potential_impact = Column(Text, nullable=False)  # Must start with [INFERENCE]
    inference_labels = Column(Text, nullable=False, default="[]")
    cvss_score = Column(Float, nullable=False)
    confidence = Column(Integer, nullable=False, default=100)
    evidence_basis = Column(Text, nullable=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


# ==============================================================================
# Phase 23: Advanced Authorized Vulnerability Research & Multi-Step Validation
# ==============================================================================

class AttackSurfaceNodeRecord(Base):
    __tablename__ = "attack_surface_nodes"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, nullable=False, index=True)
    target = Column(String, nullable=False)
    node_type = Column(String, nullable=False, index=True)
    canonical_url = Column(String, nullable=False, index=True)
    endpoint = Column(String, nullable=True)
    parameter = Column(String, nullable=True)
    method = Column(String, nullable=True)
    source = Column(String, nullable=False)
    observation_hash = Column(String, nullable=False, index=True)
    confidence = Column(Float, nullable=False, default=1.0)
    status = Column(String, nullable=False, default="OBSERVED")
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class AttackSurfaceEdgeRecord(Base):
    __tablename__ = "attack_surface_edges"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, nullable=False, index=True)
    source_node_id = Column(String, nullable=False, index=True)
    destination_node_id = Column(String, nullable=False, index=True)
    edge_type = Column(String, nullable=False, index=True)
    evidence_id = Column(String, nullable=True)
    confidence = Column(Float, nullable=False, default=1.0)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class ValidationPlanRecord(Base):
    __tablename__ = "validation_plans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, nullable=False, index=True)
    hypothesis_id = Column(String, nullable=False, index=True)
    target = Column(String, nullable=False)
    plan_version = Column(String, nullable=False, default="1.0.0")
    steps_json = Column(Text, nullable=False, default="[]")
    estimated_requests = Column(Integer, nullable=False, default=1)
    allowed_methods = Column(Text, nullable=False, default='["GET","HEAD","OPTIONS"]')
    success_conditions = Column(Text, nullable=False, default="[]")
    failure_conditions = Column(Text, nullable=False, default="[]")
    inconclusive_conditions = Column(Text, nullable=False, default="[]")
    safety_constraints = Column(Text, nullable=False, default="{}")
    authorization_status = Column(String, nullable=False, default="HUMAN_REVIEW_REQUIRED")
    status = Column(String, nullable=False, default="DRAFT", index=True)
    operator_approval_id = Column(String, nullable=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class ValidationPlanStepRecord(Base):
    __tablename__ = "validation_plan_steps"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    validation_plan_id = Column(String, nullable=False, index=True)
    step_number = Column(Integer, nullable=False, index=True)
    method = Column(String, nullable=False, default="GET")
    endpoint = Column(String, nullable=False)
    request_template = Column(Text, nullable=False, default="{}")
    prerequisite_step = Column(Integer, nullable=True)
    expected_observation = Column(Text, nullable=True)
    success_condition = Column(Text, nullable=True)
    failure_condition = Column(Text, nullable=True)
    request_cost = Column(Integer, nullable=False, default=1)
    status = Column(String, nullable=False, default="PENDING", index=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class ValidationObservationRecord(Base):
    __tablename__ = "validation_observations"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    validation_plan_id = Column(String, nullable=False, index=True)
    step_id = Column(String, nullable=False, index=True)
    request_number = Column(Integer, nullable=False)
    status = Column(String, nullable=False)
    status_code = Column(Integer, nullable=True)
    response_hash = Column(String, nullable=True)
    normalized_response_hash = Column(String, nullable=True)
    observation_type = Column(String, nullable=False, index=True)
    observation_details = Column(Text, nullable=True)
    comparison_result = Column(Text, nullable=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class ValidationReproductionRecord(Base):
    __tablename__ = "validation_reproductions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    validation_plan_id = Column(String, nullable=False, index=True)
    finding_id = Column(String, nullable=False, index=True)
    attempt_number = Column(Integer, nullable=False)
    result = Column(String, nullable=False)
    evidence_hash = Column(String, nullable=False)
    reproducibility_score = Column(Float, nullable=False, default=0.0)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class Phase23ConfidenceAssessmentRecord(Base):
    __tablename__ = "phase23_confidence_assessments"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    validation_plan_id = Column(String, nullable=False, index=True)
    finding_id = Column(String, nullable=False, index=True)
    evidence_score = Column(Float, nullable=False)
    consistency_score = Column(Float, nullable=False)
    reproducibility_score = Column(Float, nullable=False)
    scope_score = Column(Float, nullable=False)
    authorization_score = Column(Float, nullable=False)
    overall_score = Column(Float, nullable=False)
    confidence_level = Column(String, nullable=False, index=True)
    rationale = Column(Text, nullable=False)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class Phase23AuditEventRecord(Base):
    __tablename__ = "phase23_audit_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, nullable=False, index=True)
    operator_id = Column(String, nullable=False)
    event_type = Column(String, nullable=False, index=True)
    event_payload = Column(Text, nullable=True)
    previous_hash = Column(String, nullable=False)
    event_hash = Column(String, nullable=False, index=True)
    timestamp = Column(UTCDateTime, default=get_utc_now, nullable=False)


class PreScanResultRecord(Base):
    __tablename__ = "pre_scan_results"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, nullable=False, index=True)
    target = Column(String, nullable=False)
    overall_status = Column(String, nullable=False, default="READY", index=True)
    dns_status = Column(String, nullable=False, default="PENDING")
    http_status = Column(String, nullable=False, default="PENDING")
    https_status = Column(String, nullable=False, default="PENDING")
    tls_status = Column(String, nullable=False, default="PENDING")
    account1_status = Column(String, nullable=False, default="NOT_APPLICABLE")
    account2_status = Column(String, nullable=False, default="NOT_APPLICABLE")
    email_otp_status = Column(String, nullable=False, default="NOT_APPLICABLE")
    api_key_status = Column(String, nullable=False, default="NOT_APPLICABLE")
    config_status = Column(String, nullable=False, default="READY")
    authorization_status = Column(String, nullable=False, default="READY")
    check_details_json = Column(Text, nullable=False, default="{}")
    warnings_json = Column(Text, nullable=False, default="[]")
    errors_json = Column(Text, nullable=False, default="[]")
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)
    updated_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class ToolExecutionRecord(Base):
    __tablename__ = "tool_execution_records"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, nullable=False, index=True)
    target = Column(String, nullable=False)
    tool_name = Column(String, nullable=False, index=True)
    tool_version = Column(String, nullable=True)
    execution_profile = Column(String, nullable=False, index=True)
    execution_status = Column(String, nullable=False, default="PENDING", index=True)
    sanitized_args_json = Column(Text, nullable=False, default="[]")
    exit_code = Column(Integer, nullable=True)
    timeout_seconds = Column(Integer, nullable=False, default=60)
    stdout_hash = Column(String, nullable=True)
    stderr_hash = Column(String, nullable=True)
    output_hash = Column(String, nullable=True, index=True)
    parsed_summary_json = Column(Text, nullable=False, default="{}")
    error_category = Column(String, nullable=True)
    started_at = Column(UTCDateTime, default=get_utc_now, nullable=False)
    completed_at = Column(UTCDateTime, nullable=True)


class AuthContextRecord(Base):
    __tablename__ = "auth_context_records"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, nullable=False, index=True)
    account_id = Column(Integer, nullable=False, index=True)
    auth_status = Column(String, nullable=False, default="UNAUTHENTICATED", index=True)
    session_handle = Column(String, nullable=False)
    auth_method = Column(String, nullable=False, default="CREDENTIALS")
    username_hint = Column(String, nullable=True)
    expires_at = Column(UTCDateTime, nullable=True)
    last_authenticated_at = Column(UTCDateTime, nullable=True)
    refresh_status = Column(String, nullable=False, default="NONE")
    metadata_json = Column(Text, nullable=False, default="{}")
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)
    updated_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("campaign_id", "account_id", name="uq_auth_ctx_campaign_account"),
    )


class ExploitabilityRecord(Base):
    __tablename__ = "exploitability_records"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, nullable=False, index=True)
    target = Column(String, nullable=False)
    finding_id = Column(String, nullable=False, index=True)
    hypothesis_id = Column(String, nullable=True, index=True)
    strategy_id = Column(String, nullable=False)
    strategy_version = Column(String, nullable=False, default="1.0.0")
    verification_state = Column(String, nullable=False, default="DETECTED", index=True)
    proof_type = Column(String, nullable=False)
    impact_classification = Column(String, nullable=False)
    evidence_hash = Column(String, nullable=False, index=True)
    reproducibility_score = Column(Float, nullable=False, default=0.0)
    operator_approval_id = Column(String, nullable=True)
    proof_details_json = Column(Text, nullable=False, default="{}")
    verified_at = Column(UTCDateTime, default=get_utc_now, nullable=False)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)


class AgentOrchestratorRunRecord(Base):
    __tablename__ = "agent_orchestrator_runs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, nullable=False, index=True)
    target = Column(String, nullable=False)
    current_stage = Column(String, nullable=False, default="PRECHECK", index=True)
    overall_status = Column(String, nullable=False, default="INITIALIZED", index=True)
    stages_json = Column(Text, nullable=False, default="{}")
    warnings_json = Column(Text, nullable=False, default="[]")
    errors_json = Column(Text, nullable=False, default="[]")
    audit_trail_hash = Column(String, nullable=True)
    started_at = Column(UTCDateTime, default=get_utc_now, nullable=False)
    completed_at = Column(UTCDateTime, nullable=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)
    updated_at = Column(UTCDateTime, default=get_utc_now, nullable=False)





# Engine and Connection Pragmas
_engine = None
_SessionLocal = None


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enforce SQLite PRAGMAs: WAL mode, 5000ms busy timeout, foreign keys ON."""
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA busy_timeout=5000;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.close()


def get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        kwargs: dict[str, Any] = {"connect_args": {"check_same_thread": False}}
        if "sqlite://" in settings.database_url and ":memory:" in settings.database_url or settings.database_url == "sqlite:///":
            kwargs["poolclass"] = StaticPool
        elif "sqlite://" in settings.database_url:
            from sqlalchemy.pool import NullPool
            kwargs["poolclass"] = NullPool
            
        _engine = create_engine(
            settings.database_url,
            **kwargs
        )
    return _engine


def get_session_factory():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(), expire_on_commit=False)
    return _SessionLocal


def get_db() -> Generator[Session, None, None]:
    factory = get_session_factory()
    db = factory()
    try:
        yield db
    finally:
        db.close()


def with_db_retry(max_retries: int = 3, delay: float = 0.1):
    """Decorator to retry DB operations on transient SQLite locks."""
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_err = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except (sqlite3.OperationalError, Exception) as e:
                    if "database is locked" in str(e).lower() or "locked" in str(e).lower():
                        last_err = e
                        time.sleep(delay * (2 ** attempt))
                    else:
                        raise e
            if last_err is not None:
                raise last_err
            raise RuntimeError("Max retries exceeded")
        return wrapper
    return decorator


def init_db() -> None:
    """Initialize database tables and run versioned migrations safely."""
    engine = get_engine()
    Base.metadata.create_all(bind=engine)

    # Determine database file path for backup support
    db_url = str(engine.url)
    db_path = None
    if "sqlite:///" in db_url:
        db_path = db_url.replace("sqlite:///", "")

    # Execute versioned migrations with pre-migration backup & checksum validation
    run_migrations(engine, db_path=db_path)
