"""AihaX Phase 8 — End-to-End Campaign Operations & Evidence Vault Integration Test."""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.database import Base, get_db
from backend.persistence.state_machine import CampaignLifecycleState


@pytest.fixture
def client():
    from backend.core.auth import get_or_create_api_token
    api_token = get_or_create_api_token()
    with TestClient(app, base_url="http://localhost:8000", headers={"Authorization": f"Bearer {api_token}"}) as test_client:
        yield test_client


def test_full_campaign_operations_lifecycle_e2e(client):
    # 1. Create campaign via API
    create_resp = client.post(
        "/api/campaigns",
        json={
            "name": "E2E Production Campaign",
            "target_url": "http://127.0.0.1:8080",
            "mode": "SAFE_SCAN",
            "campaign_budget": 200,
            "target_budget": 50,
            "check_budget": 15,
            "in_scope_assets": ["http://127.0.0.1:8080", "http://127.0.0.1:8080/api"],
        },
    )
    assert create_resp.status_code == 201, create_resp.text
    campaign_data = create_resp.json()["data"]
    campaign_id = campaign_data["campaign_id"]
    assert campaign_data["status"] == "DRAFT"

    # 2. Cannot start without authorization (fail-closed)
    start_unauth_resp = client.post(f"/api/campaigns/{campaign_id}/start")
    assert start_unauth_resp.status_code == 403

    # 3. Authorize campaign
    auth_resp = client.post(
        f"/api/campaigns/{campaign_id}/authorize",
        json={
            "authorized_by": "lead_security_engineer",
            "authorization_type": "explicit_written_consent",
            "authorization_reference": "SECURITY-TICKET-8899",
            "duration_days": 14,
        },
    )
    assert auth_resp.status_code == 200
    assert auth_resp.json()["data"]["status"] == "AUTHORIZED"

    # 4. Start campaign
    start_resp = client.post(f"/api/campaigns/{campaign_id}/start")
    assert start_resp.status_code == 200
    assert start_resp.json()["data"]["status"] == "RUNNING"

    # 5. Pause campaign
    pause_resp = client.post(f"/api/campaigns/{campaign_id}/pause")
    assert pause_resp.status_code == 200
    assert pause_resp.json()["data"]["status"] == "PAUSED"

    # 6. Resume campaign
    resume_resp = client.post(f"/api/campaigns/{campaign_id}/resume")
    assert resume_resp.status_code == 200
    assert resume_resp.json()["data"]["status"] == "RUNNING"

    # 7. Check audit trail via API
    audit_resp = client.get(f"/api/campaigns/{campaign_id}/audit")
    assert audit_resp.status_code == 200
    events = audit_resp.json()["data"]
    assert len(events) >= 4
    event_types = [e["event_type"] for e in events]
    assert "campaign_created" in event_types
    assert "campaign_authorized" in event_types
    assert "campaign_running" in event_types
    assert "campaign_paused" in event_types

    # 8. Check cryptographic integrity via API
    integrity_resp = client.get(f"/api/campaigns/{campaign_id}/integrity")
    assert integrity_resp.status_code == 200
    assert integrity_resp.json()["data"]["verified"] is True

    # 9. Check coverage endpoint
    coverage_resp = client.get(f"/api/campaigns/{campaign_id}/coverage")
    assert coverage_resp.status_code == 200
    assert coverage_resp.json()["data"]["targets_total"] >= 1

    # 10. Check findings endpoint
    findings_resp = client.get(f"/api/campaigns/{campaign_id}/findings")
    assert findings_resp.status_code == 200
    assert isinstance(findings_resp.json()["data"], list)

    # 11. Check evidence endpoint
    evidence_resp = client.get(f"/api/campaigns/{campaign_id}/evidence")
    assert evidence_resp.status_code == 200
    assert "items" in evidence_resp.json()["data"]

    # 12. Check reports endpoint
    reports_resp = client.post(f"/api/campaigns/{campaign_id}/reports")
    assert reports_resp.status_code == 200
    assert "reports" in reports_resp.json()

    # 13. Check metrics endpoint
    metrics_resp = client.get("/api/campaigns/metrics/operational")
    assert metrics_resp.status_code == 200
    assert metrics_resp.json()["data"]["campaigns_total"] >= 1
