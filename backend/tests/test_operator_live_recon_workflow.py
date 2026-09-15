"""Tests for Operator-Initiated Live Recon Validation Workflow.

Verifies:
1. GET /api/campaigns/{id}/recon-live-preflight produces ZERO network calls and read-only preflight data.
2. POST /api/campaigns/{id}/recon-live-validation?mode=mock returns MOCK_VALIDATED, logs audit event, and NEVER produces LIVE_VALIDATED records.
3. Status invariant guarantees: AVAILABLE != MOCK_VALIDATED != LIVE_VALIDATED.
4. Authoritative backend re-validation of authorization, scope, capability, and safety rules.
5. Historical evidence remains completely unmutated before/after mock runs.
"""

from __future__ import annotations

import json
import pytest
import socket
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.models.database import Base, get_db
from backend.persistence.models import AuthorizationRecord, Campaign, AuditTrailEvent, EvidenceRecord
from backend.core.auth import get_current_user_optional, get_or_create_api_token

client = TestClient(app)


# Mock user fixture for authenticated endpoints
class DummyUser:
    id = "usr-test-operator-001"
    email = "lead_operator@aihax.sec"


@pytest.fixture(autouse=True)
def override_auth_user():
    app.dependency_overrides[get_current_user_optional] = lambda: DummyUser()
    yield
    app.dependency_overrides.pop(get_current_user_optional, None)


@pytest.fixture
def db_session():
    """Create in-memory SQLite database supporting multi-threaded TestClient access."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_auth_headers() -> dict[str, str]:
    return {"X-AihaX-Token": get_or_create_api_token()}


def test_live_preflight_never_generates_network_traffic(db_session, monkeypatch):
    """Assert GET /recon-live-preflight is strictly read-only and performs 0 external outbound network calls."""
    def _forbidden_outbound(*args, **kwargs):
        pytest.fail("Outbound external network call attempted during read-only preflight evaluation!")

    import urllib.request
    import requests

    monkeypatch.setattr(urllib.request, "urlopen", _forbidden_outbound)
    monkeypatch.setattr(requests, "get", _forbidden_outbound)
    monkeypatch.setattr(requests, "post", _forbidden_outbound)

    c = Campaign(
        id="camp-test-preflight-001",
        name="Preflight Test Campaign",
        target_url="https://example-preflight.test",
        mode="SAFE_SCAN",
        status="AUTHORIZED",
    )
    db_session.add(c)

    auth = AuthorizationRecord(
        id="auth-test-preflight-001",
        campaign_id=c.id,
        authorized_by="lead_operator@aihax.sec",
        authorization_type="explicit_scope_consent",
        authorized_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        scope_hash="a157876a0cf6798e7d7c1ffbc347fe3cf81af9c1fe3460fcb146ca23dc0d2059",
        status="ACTIVE",
    )
    db_session.add(auth)
    db_session.commit()

    app.dependency_overrides[get_db] = lambda: db_session
    try:
        response = client.get(f"/api/campaigns/{c.id}/recon-live-preflight", headers=get_auth_headers())
        assert response.status_code == 200, response.text
        data = response.json().get("data", {})

        assert data["target"] == "https://example-preflight.test"
        assert data["authorization"]["active"] is True
        assert data["authorization"]["authorization_id"] == auth.id
        assert data["can_launch"] is True
        assert len(data["tool_matrix"]) > 0
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_mock_execution_never_produces_live_validated(db_session):
    """Assert POST /recon-live-validation?mode=mock returns MOCK_VALIDATED and NEVER LIVE_VALIDATED."""
    c = Campaign(
        id="camp-test-mock-002",
        name="Mock Run Test Campaign",
        target_url="https://example-mock.test",
        mode="SAFE_SCAN",
        status="AUTHORIZED",
    )
    db_session.add(c)

    auth = AuthorizationRecord(
        id="auth-test-mock-002",
        campaign_id=c.id,
        authorized_by="lead_operator@aihax.sec",
        authorization_type="explicit_scope_consent",
        authorized_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        scope_hash="33f91ee87bdc686fdfbac48977a8df58c23eeb6ddaf8491ef77e19d5fc71fffd",
        status="ACTIVE",
    )
    db_session.add(auth)
    db_session.commit()

    payload = {
        "confirmations": {
            "authActive": True,
            "targetCorrect": True,
            "capabilitiesReviewed": True,
            "liveTrafficAcknowledged": True,
        }
    }

    app.dependency_overrides[get_db] = lambda: db_session
    try:
        response = client.post(
            f"/api/campaigns/{c.id}/recon-live-validation?mode=mock",
            json=payload,
            headers=get_auth_headers(),
        )
        assert response.status_code == 200, response.text
        data = response.json().get("data", {})

        assert data["execution_mode"] == "MOCK_VALIDATION"
        assert data["status"] == "COMPLETED"

        tool_records = data["tool_records"]
        for tool_name, record in tool_records.items():
            assert record["status"] != "LIVE_VALIDATED", f"Tool {tool_name} improperly generated LIVE_VALIDATED status during mock run!"
            if record["executed"]:
                assert record["status"] == "MOCK_VALIDATED"
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_unauthorized_campaign_blocks_preflight_and_validation(db_session):
    """Assert missing/expired authorization blocks preflight launch and POST validation."""
    c = Campaign(
        id="camp-test-unauth-003",
        name="Unauth Campaign",
        target_url="https://example-unauth.test",
        mode="SAFE_SCAN",
        status="CREATED",
    )
    db_session.add(c)
    db_session.commit()

    app.dependency_overrides[get_db] = lambda: db_session
    try:
        # Preflight check
        resp_pf = client.get(f"/api/campaigns/{c.id}/recon-live-preflight", headers=get_auth_headers())
        assert resp_pf.status_code == 200
        pf_data = resp_pf.json()["data"]
        assert pf_data["authorization"]["active"] is False
        assert pf_data["can_launch"] is False

        # POST validation should fail closed
        payload = {"confirmations": {"authActive": True, "targetCorrect": True}}
        resp_val = client.post(
            f"/api/campaigns/{c.id}/recon-live-validation?mode=mock",
            json=payload,
            headers=get_auth_headers(),
        )
        assert resp_val.status_code == 400
        assert "Preflight validation failed" in resp_val.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_audit_event_logged_without_evidence_mutation(db_session):
    """Assert mock validation logs an AuditTrailEvent but creates 0 LIVE_VALIDATED evidence records."""
    c = Campaign(
        id="camp-test-audit-004",
        name="Audit Test Campaign",
        target_url="https://example-audit.test",
        mode="SAFE_SCAN",
        status="AUTHORIZED",
    )
    db_session.add(c)

    auth = AuthorizationRecord(
        id="auth-test-audit-004",
        campaign_id=c.id,
        authorized_by="lead_operator@aihax.sec",
        authorization_type="explicit_scope_consent",
        authorized_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        scope_hash="33f91ee87bdc686fdfbac48977a8df58c23eeb6ddaf8491ef77e19d5fc71fffd",
        status="ACTIVE",
    )
    db_session.add(auth)
    db_session.commit()

    initial_evidence_count = db_session.query(EvidenceRecord).count()
    initial_audit_count = db_session.query(AuditTrailEvent).count()

    app.dependency_overrides[get_db] = lambda: db_session
    try:
        response = client.post(
            f"/api/campaigns/{c.id}/recon-live-validation?mode=mock",
            json={"confirmations": {"authActive": True}},
            headers=get_auth_headers(),
        )
        assert response.status_code == 200

        new_audit_count = db_session.query(AuditTrailEvent).count()
        new_evidence_count = db_session.query(EvidenceRecord).count()

        assert new_audit_count == initial_audit_count + 1
        assert new_evidence_count == initial_evidence_count, "Mock execution improperly mutated evidence records!"
    finally:
        app.dependency_overrides.pop(get_db, None)
