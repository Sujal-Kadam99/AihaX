"""Automated Safety and Invariant Regression Tests for Eternal/Zomato Campaign."""

import json
import uuid
from datetime import datetime, timezone
import pytest

from backend.core.scope_validator import ScopeValidator, ScopeStatus
from backend.evidence.integrity import compute_evidence_content_hash, compute_evidence_chain_hash
from backend.evidence.redaction import contains_unredacted_secrets, redact_secrets
from backend.persistence.models import Base
from backend.persistence.repository import CampaignRepository
from backend.persistence.state_machine import CampaignLifecycleState, TaskLifecycleState
from backend.services.campaign_operations import CampaignOperationsService
from backend.services.finding_deduplicator import FindingLifecycleState, can_transition
from backend.services.request_engine import (
    MockTransport,
    RawResponse,
    RequestEngine,
    RequestSpec,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture
def memory_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def zomato_scope_validator():
    return ScopeValidator(
        in_scope_assets=["https://*.zomato.com/*", "http://*.zomato.com/*", "*.zomato.com", "zomato.com"],
        out_of_scope_assets=[
            "https://evil.com/*",
            "*.blinkit.com",
            "*.feedingindia.org",
            "*.hyperpure.com",
            "*.external.com",
        ],
        excluded_ports=[22, 25, 445, 3389, 8080],
        allowed_ports=[80, 443],
    )


@pytest.mark.asyncio
async def test_eternal_zomato_scope_isolation_and_zero_network_bytes(zomato_scope_validator):
    transport = MockTransport()
    transport.register_response(
        "GET",
        "https://www.zomato.com/api/v1/search",
        RawResponse(status_code=200, headers={"content-type": "application/json"}, body=b'{"restaurants":[]}'),
    )
    engine = RequestEngine(scope_validator=zomato_scope_validator, transport=transport)

    # 1. Allowed in-scope target
    spec_ok = RequestSpec(url="https://www.zomato.com/api/v1/search", authorization_confirmed=True)
    ev_ok = await engine.execute(spec_ok)
    assert ev_ok.success is True
    assert transport.call_count == 1

    # 2. Out of scope target (Zero network bytes)
    spec_evil = RequestSpec(url="https://evil.com/leak", authorization_confirmed=True)
    ev_evil = await engine.execute(spec_evil)
    assert ev_evil.success is False
    assert ev_evil.transport_error["error_type"] == "SCOPE_DENIED"
    assert transport.call_count == 1  # 0 additional transport calls!

    # 3. Non-zomato Eternal domain blocked (Strict isolation)
    spec_blinkit = RequestSpec(url="https://admin.blinkit.com/api", authorization_confirmed=True)
    ev_blinkit = await engine.execute(spec_blinkit)
    assert ev_blinkit.success is False
    assert ev_blinkit.transport_error["error_type"] == "SCOPE_DENIED"
    assert transport.call_count == 1


@pytest.mark.asyncio
async def test_eternal_zomato_redirect_leaving_scope_blocked(zomato_scope_validator):
    transport = MockTransport()
    transport.register_response(
        url_prefix="https://www.zomato.com/redirect",
        status_code=302,
        headers={"location": "https://attacker.com/steal"},
        body="",
    )
    engine = RequestEngine(scope_validator=zomato_scope_validator, transport=transport)

    spec = RequestSpec(url="https://www.zomato.com/redirect", follow_redirects=True, authorization_confirmed=True)
    ev = await engine.execute(spec)
    assert ev.success is False
    assert ev.transport_error["error_type"] == "REDIRECT_BLOCKED"


@pytest.mark.asyncio
async def test_eternal_zomato_excluded_ports_blocked(zomato_scope_validator):
    transport = MockTransport()
    engine = RequestEngine(scope_validator=zomato_scope_validator, transport=transport)

    spec = RequestSpec(url="https://www.zomato.com:22/ssh", authorization_confirmed=True)
    ev = await engine.execute(spec)
    assert ev.success is False
    assert ev.transport_error["error_type"] == "SCOPE_DENIED"
    assert transport.call_count == 0


def test_eternal_zomato_campaign_creation_and_authorization(memory_db):
    repo = CampaignRepository(memory_db)
    ops = CampaignOperationsService(repo)

    camp = ops.create_campaign(
        name="Eternal-Zomato-Web-001",
        target_url="https://www.zomato.com",
        mode="CONTROLLED_HUMAN_IN_THE_LOOP",
        campaign_budget=250,
        target_budget=50,
        check_budget=10,
        max_concurrency=2,
        in_scope_assets=["https://*.zomato.com/*", "http://*.zomato.com/*", "*.zomato.com", "zomato.com"],
    )
    memory_db.commit()
    assert camp.status == "DRAFT"
    assert camp.max_concurrency == 2
    assert camp.campaign_budget == 250

    # Authorization step
    auth = ops.authorize_campaign(
        campaign_id=camp.id,
        authorized_by="lead_security_operator",
        authorization_type="explicit_scope_consent",
        authorization_reference="H1-ETERNAL-ZOMATO-AUTH-001",
    )
    memory_db.commit()
    assert camp.status == "AUTHORIZED"
    assert auth.authorization_reference == "H1-ETERNAL-ZOMATO-AUTH-001"


def test_eternal_zomato_human_in_the_loop_finding_state_machine():
    # Candidates must transition through human review before being verified
    assert can_transition(FindingLifecycleState.DISCOVERED, FindingLifecycleState.CANDIDATE) is True
    assert can_transition(FindingLifecycleState.CANDIDATE, FindingLifecycleState.NEEDS_HUMAN_REVIEW) is True
    assert can_transition(FindingLifecycleState.NEEDS_HUMAN_REVIEW, FindingLifecycleState.VERIFICATION_REQUESTED) is True
    assert can_transition(FindingLifecycleState.VERIFICATION_REQUESTED, FindingLifecycleState.VERIFIED) is True
    assert can_transition(FindingLifecycleState.VERIFIED, FindingLifecycleState.REPORT_READY) is True

    # Automatic verification bypass is blocked
    assert can_transition(FindingLifecycleState.DISCOVERED, FindingLifecycleState.VERIFIED) is False
    assert can_transition(FindingLifecycleState.CANDIDATE, FindingLifecycleState.REPORTABLE) is False
    assert can_transition(FindingLifecycleState.REJECTED, FindingLifecycleState.REPORTABLE) is False


def test_eternal_zomato_secret_redaction_and_evidence_integrity():
    raw_poc = (
        "GET /api/account HTTP/1.1\n"
        "Host: api.zomato.com\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MTIzfQ.UNREDACTED_SECRET\n"
        "Cookie: auth_token=super_secret_cookie_token_999\n"
    )
    redacted = redact_secrets(raw_poc)
    assert "UNREDACTED_SECRET" not in redacted
    assert "super_secret_cookie_token_999" not in redacted
    assert not contains_unredacted_secrets(redacted)

    # Compute deterministic SHA-256 hash
    h1 = compute_evidence_content_hash("PROOF", "https://api.zomato.com/api/account", "GET", redacted, "200 OK")
    h2 = compute_evidence_content_hash("PROOF", "https://api.zomato.com/api/account", "GET", redacted, "200 OK")
    assert h1 == h2
    assert len(h1) == 64
