"""Unit and Integration Tests for Phase 14: Production Bug-Bounty Execution Readiness & Authorization Safety."""

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.core.scope_validator import (
    ScopeDecision,
    ScopeStatus,
    ScopeValidator,
    validate_concrete_target_url,
    validate_destination_safety,
)
from backend.models.database import Base, Program, ProgramScope
from backend.persistence.models import (
    AuditTrailEvent,
    AuthorizationRecord,
    Campaign,
    CampaignSnapshot,
    ExecutionTask,
)
from backend.persistence.repository import CampaignRepository
from backend.services.campaign_operations import (
    AuthorizationRequiredException,
    CampaignOperationsService,
    ScopeMismatchException,
)
from backend.services.campaign_worker import CampaignWorker
from backend.services.request_engine import (
    MockTransport,
    RawResponse,
    RequestEngine,
    RequestEvidence,
    RequestSpec,
    TransportError,
)


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def repo(db_session):
    return CampaignRepository(db_session)


@pytest.fixture
def ops(repo):
    return CampaignOperationsService(repo)


# ──────────────────────────────────────────────────────────────────────────────
# 1. Target URL & SSRF Safety
# ──────────────────────────────────────────────────────────────────────────────

def test_concrete_target_url_validation_success():
    scheme, host, port, path, can_url = validate_concrete_target_url("https://shop.example.com/login")
    assert scheme == "https"
    assert host == "shop.example.com"
    assert port == 443
    assert path == "/login"
    assert can_url == "https://shop.example.com/login"


def test_wildcard_target_url_rejected():
    with pytest.raises(ValueError, match="Wildcard scope rules cannot be used"):
        validate_concrete_target_url("*.example.com")

    with pytest.raises(ValueError, match="Wildcard scope rules cannot be used"):
        validate_concrete_target_url("https://*.example.com")


def test_ssrf_metadata_ip_rejected():
    with pytest.raises(ValueError, match="prohibited cloud metadata endpoint"):
        validate_concrete_target_url("http://169.254.169.254/latest/meta-data/")


def test_ssrf_metadata_hostname_rejected():
    with pytest.raises(ValueError, match="prohibited cloud metadata"):
        validate_concrete_target_url("http://metadata.google.internal/computeMetadata/v1/")


def test_validate_destination_safety_link_local():
    is_safe, reason = validate_destination_safety("http://169.254.10.20/admin")
    assert not is_safe
    assert "link-local" in reason.lower()


# ──────────────────────────────────────────────────────────────────────────────
# 2. Authorization Record & Expiration
# ──────────────────────────────────────────────────────────────────────────────

def test_authorization_record_creation_and_expiry(ops, repo, db_session):
    campaign = ops.create_campaign(
        name="Auth Test Campaign",
        target_url="https://app.example.com",
    )
    db_session.commit()

    auth = ops.authorize_campaign(
        campaign_id=campaign.id,
        authorized_by="security_lead",
        duration_days=7,
    )
    db_session.commit()

    assert auth.status == "ACTIVE"
    assert auth.authorized_by == "security_lead"
    assert auth.expires_at > datetime.now(timezone.utc)
    assert campaign.status == "AUTHORIZED"


def test_expired_authorization_fails_closed(ops, repo, db_session):
    campaign = ops.create_campaign(
        name="Expired Campaign",
        target_url="https://app.example.com",
    )
    db_session.commit()

    auth = ops.authorize_campaign(
        campaign_id=campaign.id,
        authorized_by="security_lead",
        duration_days=1,
    )
    # Force expired date
    auth.expires_at = datetime.now(timezone.utc) - timedelta(hours=2)
    db_session.commit()

    with pytest.raises(AuthorizationRequiredException, match="authorization expired"):
        ops.start_campaign(campaign.id)


def test_missing_authorization_fails_closed(ops, repo, db_session):
    campaign = ops.create_campaign(
        name="Unauth Campaign",
        target_url="https://app.example.com",
    )
    db_session.commit()

    with pytest.raises(AuthorizationRequiredException, match="no authorization record found"):
        ops.start_campaign(campaign.id)


# ──────────────────────────────────────────────────────────────────────────────
# 3. Scope Snapshot Integrity & Tamper Resistance
# ──────────────────────────────────────────────────────────────────────────────

def test_scope_snapshot_integrity_verified(ops, repo, db_session):
    campaign = ops.create_campaign(
        name="Snapshot Test Campaign",
        target_url="https://app.example.com",
    )
    db_session.commit()

    ops.authorize_campaign(campaign.id, authorized_by="lead_op")
    db_session.commit()

    ok, reason = ops.verify_scope_snapshot_integrity(campaign.id)
    assert ok
    assert "verified" in reason.lower()


def test_scope_snapshot_tampering_detected(ops, repo, db_session):
    campaign = ops.create_campaign(
        name="Tamper Test Campaign",
        target_url="https://app.example.com",
    )
    db_session.commit()

    ops.authorize_campaign(campaign.id, authorized_by="lead_op")
    db_session.commit()

    snap = repo.get_snapshot(campaign.id)
    snap.snapshot_json = json.dumps({"tampered": True, "scope_assets": ["https://evil.com"]})
    db_session.commit()

    ok, reason = ops.verify_scope_snapshot_integrity(campaign.id)
    assert not ok
    assert "tampering detected" in reason.lower()

    with pytest.raises(ScopeMismatchException):
        ops.start_campaign(campaign.id)


# ──────────────────────────────────────────────────────────────────────────────
# 4. Pre-Flight Checklist
# ──────────────────────────────────────────────────────────────────────────────

def test_get_campaign_preflight_checklist(ops, repo, db_session):
    campaign = ops.create_campaign(
        name="Preflight Campaign",
        target_url="https://app.example.com",
    )
    db_session.commit()

    # Before authorization: should not be all passed
    checklist_before = ops.get_campaign_preflight_checklist(campaign.id)
    assert not checklist_before["all_passed"]
    assert not checklist_before["campaign_authorized"]

    # Authorize
    ops.authorize_campaign(campaign.id, authorized_by="lead_op", duration_days=30)
    db_session.commit()

    checklist_after = ops.get_campaign_preflight_checklist(campaign.id)
    assert checklist_after["all_passed"]
    assert checklist_after["campaign_authorized"]
    assert checklist_after["target_concrete_valid"]
    assert checklist_after["authorization_not_expired"]
    assert checklist_after["scope_snapshot_verified"]
    assert checklist_after["budget_available"]
    assert checklist_after["request_engine_ready"]


# ──────────────────────────────────────────────────────────────────────────────
# 5. Worker Pre-Execution Hardening
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_worker_fails_task_on_expired_authorization(ops, repo, db_session):
    campaign = ops.create_campaign(
        name="Worker Expired Test",
        target_url="https://app.example.com",
    )
    db_session.commit()

    auth = ops.authorize_campaign(campaign.id, authorized_by="lead_op", duration_days=10)
    ops.start_campaign(campaign.id, auto_dispatch=True)
    db_session.commit()

    # Expire auth after start
    auth.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    db_session.commit()

    worker = CampaignWorker(worker_id="test_w1")
    claimed = repo.claim_tasks(campaign.id, worker_id="test_w1", limit=1)
    assert len(claimed) == 1

    res = await worker.execute_task(claimed[0].id, db_session, repo)
    assert res.get("status") == "failed"
    assert "authorization" in res.get("error", "").lower()


@pytest.mark.asyncio
async def test_worker_fails_task_on_budget_exhaustion(ops, repo, db_session):
    campaign = ops.create_campaign(
        name="Worker Budget Test",
        target_url="https://app.example.com",
        campaign_budget=2,
    )
    db_session.commit()

    ops.authorize_campaign(campaign.id, authorized_by="lead_op")
    ops.start_campaign(campaign.id, auto_dispatch=True)
    campaign.requests_used = 2  # Budget reached
    db_session.commit()

    worker = CampaignWorker(worker_id="test_w2")
    claimed = repo.claim_tasks(campaign.id, worker_id="test_w2", limit=1)
    assert len(claimed) == 1

    res = await worker.execute_task(claimed[0].id, db_session, repo)
    assert res.get("status") == "failed"
    assert "budget exhausted" in res.get("error", "").lower()


# ──────────────────────────────────────────────────────────────────────────────
# 6. Redirect to Cloud Metadata Blocking
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_redirect_to_cloud_metadata_blocked():
    validator = ScopeValidator(in_scope_assets=["http://127.0.0.1:8080"])
    mock_transport = MockTransport()
    mock_transport.register_response(
        "http://127.0.0.1:8080/meta-redirect",
        status_code=302,
        headers={"Location": "http://169.254.169.254/latest/meta-data/"},
    )

    req_engine = RequestEngine(scope_validator=validator, transport=mock_transport)
    ev = await req_engine.execute(
        RequestSpec(url="http://127.0.0.1:8080/meta-redirect", follow_redirects=True)
    )

    assert not ev.success
    assert ev.transport_error is not None
    assert ev.transport_error["error_type"] == "REDIRECT_BLOCKED"
