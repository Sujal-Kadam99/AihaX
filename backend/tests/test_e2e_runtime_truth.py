"""End-to-End Runtime Truth & Verification Smoke Test for AihaX."""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.core.auth import get_or_create_api_token
from backend.main import app
from backend.models.database import Base, Finding, Scan, get_db
from backend.persistence.models import (
    Campaign,
    EvidenceRecord,
    ExecutionTask,
)
from backend.persistence.repository import CampaignRepository
from backend.persistence.state_machine import TaskLifecycleState


@pytest.fixture
def test_db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    session = TestingSessionLocal()

    def override_get_db():
        try:
            yield session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield session
    finally:
        app.dependency_overrides.pop(get_db, None)
        session.close()


@pytest.fixture
def auth_headers():
    token = get_or_create_api_token()
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client(test_db_session):
    return TestClient(app)


def test_complete_e2e_campaign_lifecycle_and_runtime_truth(test_db_session, client, auth_headers):
    # ── Stage 1: Create Campaign (POST /api/campaigns) ────────────────────────
    create_payload = {
        "name": "E2E-Smoke-Zomato-001",
        "target_url": "https://www.zomato.com",
        "mode": "CONTROLLED_HUMAN_IN_THE_LOOP",
        "campaign_budget": 200,
        "target_budget": 50,
        "check_budget": 10,
        "in_scope_assets": ["*.zomato.com", "https://*.zomato.com/*"],
    }
    create_resp = client.post("/api/campaigns", json=create_payload, headers=auth_headers)
    assert create_resp.status_code == 201, create_resp.text
    camp_data = create_resp.json()["data"]
    campaign_id = camp_data["campaign_id"]
    assert camp_data["status"] == "DRAFT"
    assert camp_data["target_url"] == "https://www.zomato.com"

    # Verify DB persistence
    repo = CampaignRepository(test_db_session)
    db_camp = repo.get_campaign(campaign_id)
    assert db_camp is not None
    assert db_camp.status == "DRAFT"

    # ── Stage 2: Authorize Campaign (POST /api/campaigns/{id}/authorize) ──────
    auth_payload = {
        "authorized_by": "lead_operator@security.local",
        "authorization_type": "explicit_scope_consent",
        "authorization_reference": "H1-ETERNAL-SMOKE-001",
        "duration_days": 14,
    }
    auth_resp = client.post(f"/api/campaigns/{campaign_id}/authorize", json=auth_payload, headers=auth_headers)
    assert auth_resp.status_code == 200, auth_resp.text
    assert auth_resp.json()["data"]["status"] == "AUTHORIZED"

    # ── Stage 3: Start Campaign (POST /api/campaigns/{id}/start) ──────────────
    start_resp = client.post(f"/api/campaigns/{campaign_id}/start", headers=auth_headers)
    assert start_resp.status_code == 200, start_resp.text
    assert start_resp.json()["data"]["status"] == "RUNNING"

    # ── Stage 4: Query Runtime Diagnostic Truth (GET /api/campaigns/{id}/runtime)
    runtime_resp = client.get(f"/api/campaigns/{campaign_id}/runtime", headers=auth_headers)
    assert runtime_resp.status_code == 200, runtime_resp.text
    runtime_truth = runtime_resp.json()["data"]
    assert runtime_truth["campaign_id"] == campaign_id
    assert runtime_truth["status"] == "RUNNING"
    assert runtime_truth["backend_state"]["status"] == "CONNECTED"
    assert runtime_truth["backend_state"]["database"] == "READY"
    assert "OPTIONAL" in runtime_truth["backend_state"]["redis"]
    assert runtime_truth["is_stalled"] is False

    # ── Stage 5: Simulate Worker Task Execution & Genuine Evidence Persistence
    repo.create_task(
        campaign_id=campaign_id,
        target_url="https://api.zomato.com/v1/auth/check",
        check_id="C009_Exposed_Admin",
        endpoint_url="https://api.zomato.com/v1/auth/check",
    )
    test_db_session.commit()

    # Worker acquires lease
    claimed_tasks = repo.claim_tasks(campaign_id=campaign_id, worker_id="smoke_worker_01", limit=10, lease_duration_seconds=60)
    assert len(claimed_tasks) > 0
    task = claimed_tasks[0]
    assert task.status == TaskLifecycleState.CLAIMED.value

    # Persist genuine Evidence Record in Vault
    from backend.evidence.integrity import compute_evidence_content_hash
    sanitized_req = "GET /v1/auth/check HTTP/1.1\nHost: api.zomato.com"
    sanitized_res = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"status\":\"authenticated\"}"
    content_hash = compute_evidence_content_hash(
        evidence_type="PROOF",
        target_url="https://api.zomato.com/v1/auth/check",
        method="GET",
        sanitized_request=sanitized_req,
        sanitized_response=sanitized_res,
    )

    ev_record = repo.record_evidence(
        campaign_id=campaign_id,
        evidence_type="PROOF",
        target_url="https://api.zomato.com/v1/auth/check",
        content_hash=content_hash,
        method="GET",
        sanitized_request=sanitized_req,
        sanitized_response=sanitized_res,
        task_id=task.id,
    )
    assert ev_record.id is not None

    # Also insert backing Scan record and verified Finding for report generation
    scan_backing = Scan(
        id=campaign_id,
        target_url="https://www.zomato.com",
        status="completed",
        created_at=datetime.now(timezone.utc),
    )
    finding = Finding(
        id="f-smoke-001",
        scan_id=campaign_id,
        agent_id=1,
        title="Unauthenticated Internal Gateway Access",
        vuln_type="C009_Exposed_Admin",
        category="admin",
        severity="high",
        affected_url="https://api.zomato.com/v1/auth/check",
        verdict="Verified",
        verification_status="VERIFIED",
        false_positive=False,
        evidence_ids=f'["{ev_record.id}"]',
    )
    test_db_session.add(scan_backing)
    test_db_session.add(finding)

    # Complete all claimed tasks
    for t in claimed_tasks:
        repo.complete_task(task_id=t.id, worker_id="smoke_worker_01")
    test_db_session.commit()

    # ── Stage 6: Query Evidence (GET /api/campaigns/{id}/evidence) ────────────
    ev_resp = client.get(f"/api/campaigns/{campaign_id}/evidence", headers=auth_headers)
    assert ev_resp.status_code == 200, ev_resp.text
    ev_data = ev_resp.json()["data"]
    assert ev_data["total_count"] == 1
    assert len(ev_data["items"]) == 1
    assert ev_data["items"][0]["evidence_type"] == "PROOF"
    assert ev_data["items"][0]["target_url"] == "https://api.zomato.com/v1/auth/check"
    assert ev_data["items"][0]["content_hash"] == content_hash

    # ── Stage 7: Query Findings (GET /api/campaigns/{id}/findings) ────────────
    find_resp = client.get(f"/api/campaigns/{campaign_id}/findings", headers=auth_headers)
    assert find_resp.status_code == 200, find_resp.text
    find_data = find_resp.json()["data"]
    assert len(find_data) == 1
    assert find_data[0]["title"] == "Unauthenticated Internal Gateway Access"
    assert find_data[0]["verification_status"] == "VERIFIED"

    # ── Stage 8: Generate Report (POST /api/campaigns/{id}/reports) ───────────
    gen_resp = client.post(f"/api/campaigns/{campaign_id}/reports", headers=auth_headers)
    assert gen_resp.status_code == 200, gen_resp.text
    assert gen_resp.json()["success"] is True
    assert gen_resp.json()["verified_findings_count"] == 1

    # ── Stage 9: Download PDF Report (GET /api/campaigns/{id}/reports/download) 
    dl_resp = client.get(f"/api/campaigns/{campaign_id}/reports/download", headers=auth_headers)
    assert dl_resp.status_code == 200, dl_resp.text
    assert dl_resp.headers["content-type"] == "application/pdf"
    assert len(dl_resp.content) > 0
    assert dl_resp.content.startswith(b"%PDF-")

    # ── Stage 10: Verify Cryptographic Integrity & Stale Detection ───────────
    integrity_resp = client.get(f"/api/campaigns/{campaign_id}/integrity", headers=auth_headers)
    assert integrity_resp.status_code == 200, integrity_resp.text
    assert integrity_resp.json()["data"]["verified"] is True
    assert len(integrity_resp.json()["data"]["issues"]) == 0

    # Test Stalled Detection with threshold=0 (all tasks completed, not currently active)
    stale_runtime_resp = client.get(f"/api/campaigns/{campaign_id}/runtime?stale_threshold_seconds=10", headers=auth_headers)
    assert stale_runtime_resp.status_code == 200
    stale_truth = stale_runtime_resp.json()["data"]
    assert stale_truth["current_phase"] in ("REPORT_READY", "VERIFICATION", "COMPLETED", "TESTING")
    assert stale_truth["metrics"]["evidence_count"] == 1
    assert stale_truth["metrics"]["findings_verified"] == 1
