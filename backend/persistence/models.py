"""AihaX Phase 8 — Persistent Campaign Models & ORM Entities.

Provides SQLAlchemy ORM representations for:
- Campaign: Persistent campaign operational state, mode, status, budget, hashes
- CampaignTarget: Per-target scope, authorization, recon, and execution status
- ExecutionTask: Persistent check execution task with worker ownership & leases
- AuthorizationRecord: Structured, verifiable authorization proof covering scope
- EvidenceRecord: Vault record for immutable, secret-redacted evidence
- AuditTrailEvent: Tamper-evident chained audit event
- CampaignSnapshot: Immutable configuration & registry snapshot at campaign start
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from backend.models.database import Base, UTCDateTime, get_utc_now


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False, index=True)
    target_url = Column(String, nullable=False)
    mode = Column(String, nullable=False, default="SAFE_SCAN")
    assessment_mode = Column(String, nullable=False, default="CONTROLLED")  # CONTROLLED or PRODUCTION_AUTHORIZED
    awaiting_target = Column(Boolean, nullable=False, default=False)  # True when campaign needs concrete target
    status = Column(String, nullable=False, default="DRAFT", index=True)

    program_id = Column(String, ForeignKey("programs.id", ondelete="SET NULL"), nullable=True, index=True)
    user_id = Column(String, nullable=True, index=True)

    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False, index=True)
    started_at = Column(UTCDateTime, nullable=True)
    completed_at = Column(UTCDateTime, nullable=True)
    paused_at = Column(UTCDateTime, nullable=True)

    scope_snapshot_hash = Column(String, nullable=True)
    config_hash = Column(String, nullable=True)
    registry_hash = Column(String, nullable=True)
    manifest_hash = Column(String, nullable=True)

    campaign_budget = Column(Integer, nullable=False, default=500)
    target_budget = Column(Integer, nullable=False, default=100)
    check_budget = Column(Integer, nullable=False, default=20)
    requests_used = Column(Integer, nullable=False, default=0)
    max_concurrency = Column(Integer, nullable=False, default=5)
    rate_limit_rps = Column(Integer, nullable=False, default=10)

    # Relationships
    targets = relationship("CampaignTarget", back_populates="campaign", cascade="all, delete-orphan")
    tasks = relationship("ExecutionTask", back_populates="campaign", cascade="all, delete-orphan")
    authorization = relationship("AuthorizationRecord", back_populates="campaign", uselist=False, cascade="all, delete-orphan")
    evidence_records = relationship("EvidenceRecord", back_populates="campaign", cascade="all, delete-orphan")
    audit_events = relationship("AuditTrailEvent", back_populates="campaign", cascade="all, delete-orphan")
    snapshot = relationship("CampaignSnapshot", back_populates="campaign", uselist=False, cascade="all, delete-orphan")


class CampaignTarget(Base):
    __tablename__ = "campaign_targets"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    normalized_url = Column(String, nullable=False, index=True)
    scope_status = Column(String, nullable=False, default="IN_SCOPE")
    auth_status = Column(String, nullable=False, default="PENDING")
    target_status = Column(String, nullable=False, default="PENDING")
    recon_status = Column(String, nullable=False, default="PENDING")
    execution_status = Column(String, nullable=False, default="PENDING")
    requests_used = Column(Integer, nullable=False, default=0)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("campaign_id", "normalized_url", name="uq_campaign_targets_campaign_url"),
    )

    campaign = relationship("Campaign", back_populates="targets")


class ExecutionTask(Base):
    __tablename__ = "campaign_tasks"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    target_id = Column(String, nullable=True)
    target_url = Column(String, nullable=False)
    check_id = Column(String, nullable=False)
    endpoint_url = Column(String, nullable=False)
    parameter_name = Column(String, nullable=True)
    status = Column(String, nullable=False, default="PENDING", index=True)
    attempt_count = Column(Integer, nullable=False, default=0)
    max_retries = Column(Integer, nullable=False, default=3)
    budget_reservation = Column(Integer, nullable=False, default=1)
    worker_id = Column(String, nullable=True)
    lease_expires_at = Column(UTCDateTime, nullable=True, index=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)
    started_at = Column(UTCDateTime, nullable=True)
    completed_at = Column(UTCDateTime, nullable=True)
    failure_reason = Column(Text, nullable=True)
    idempotency_key = Column(String, unique=True, nullable=True, index=True)

    campaign = relationship("Campaign", back_populates="tasks")


class AuthorizationRecord(Base):
    __tablename__ = "authorization_records"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    authorized_by = Column(String, nullable=False)
    authorization_type = Column(String, nullable=False, default="explicit_scope_consent")
    authorization_reference = Column(Text, nullable=True)
    authorized_at = Column(UTCDateTime, default=get_utc_now, nullable=False)
    expires_at = Column(UTCDateTime, nullable=False)
    scope_hash = Column(String, nullable=False)
    status = Column(String, nullable=False, default="ACTIVE", index=True)

    campaign = relationship("Campaign", back_populates="authorization")


class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String, nullable=True, index=True)
    task_id = Column(String, nullable=True, index=True)
    request_id = Column(String, nullable=True)
    evidence_type = Column(String, nullable=False)
    target_url = Column(String, nullable=False)
    method = Column(String, nullable=False, default="GET")
    sanitized_request = Column(Text, nullable=True)
    sanitized_response = Column(Text, nullable=True)
    payload_summary = Column(Text, nullable=True)
    content_hash = Column(String, nullable=False, index=True)
    chain_hash = Column(String, nullable=True)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    campaign = relationship("Campaign", back_populates="evidence_records")


class AuditTrailEvent(Base):
    __tablename__ = "audit_trail_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(UTCDateTime, default=get_utc_now, nullable=False, index=True)
    actor = Column(String, nullable=False, default="system")
    event_type = Column(String, nullable=False, index=True)
    object_id = Column(String, nullable=True)
    metadata_json = Column(Text, nullable=True)
    previous_event_hash = Column(String, nullable=True)
    event_hash = Column(String, nullable=False)

    campaign = relationship("Campaign", back_populates="audit_events")


class CampaignSnapshot(Base):
    __tablename__ = "campaign_snapshots"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    campaign_id = Column(String, ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    snapshot_json = Column(Text, nullable=False)
    snapshot_hash = Column(String, nullable=False)
    created_at = Column(UTCDateTime, default=get_utc_now, nullable=False)

    campaign = relationship("Campaign", back_populates="snapshot")
