"""Tests for Report Generation and PDF Download across Scan and Campaign entities."""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.core.auth import get_or_create_api_token
from backend.main import app
from backend.models.database import Base, Finding, Scan, get_db
from backend.persistence.models import Campaign
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


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


def test_download_scan_report_pdf(test_db_session, client, auth_headers):
    # 1. Create completed Scan entity with a verified finding
    scan = Scan(
        id="scan-test-001",
        target_url="https://example.com",
        status="completed",
        scan_depth="deep",
        scan_mode="standard",
        created_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    finding = Finding(
        id="f-001",
        scan_id=scan.id,
        agent_id=1,
        title="Test XSS Vulnerability",
        vuln_type="C001_Reflected_XSS",
        category="xss",
        severity="high",
        affected_url="https://example.com/search",
        affected_param="q",
        payload="<script>alert(1)</script>",
        proof_response="Search results for <script>alert(1)</script>",
        verdict="Verified",
        verification_status="VERIFIED",
        false_positive=False,
    )
    test_db_session.add(scan)
    test_db_session.add(finding)
    test_db_session.commit()

    resp = client.get(f"/api/reports/scan/{scan.id}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF-")


def test_download_campaign_report_via_reports_route(test_db_session, client, auth_headers):
    # 2. Create Campaign entity (Phase 8 model) + backing Scan record
    camp_id = "camp-test-001"
    scan_backing = Scan(
        id=camp_id,
        target_url="https://www.zomato.com",
        status="completed",
        created_at=datetime.now(timezone.utc),
    )
    camp = Campaign(
        id=camp_id,
        name="Eternal-Zomato-Web-001",
        target_url="https://www.zomato.com",
        mode="CONTROLLED_HUMAN_IN_THE_LOOP",
        status="AUTHORIZED",
        campaign_budget=250,
        requests_used=12,
        created_at=datetime.now(timezone.utc),
    )
    finding = Finding(
        id="f-camp-001",
        scan_id=camp_id,
        agent_id=1,
        title="Open API Endpoint Without Authentication",
        vuln_type="C009_Exposed_Admin",
        category="admin",
        severity="medium",
        affected_url="https://www.zomato.com/api/internal",
        verdict="Verified",
        verification_status="VERIFIED",
        false_positive=False,
    )
    test_db_session.add(scan_backing)
    test_db_session.add(camp)
    test_db_session.add(finding)
    test_db_session.commit()

    # Hit /api/reports/scan/{camp_id} -> Resolves Campaign successfully
    resp_scan_route = client.get(f"/api/reports/scan/{camp.id}", headers=auth_headers)
    assert resp_scan_route.status_code == 200
    assert resp_scan_route.headers["content-type"] == "application/pdf"
    assert resp_scan_route.content.startswith(b"%PDF-")

    # Hit /api/reports/campaign/{camp_id}
    resp_camp_route = client.get(f"/api/reports/campaign/{camp.id}", headers=auth_headers)
    assert resp_camp_route.status_code == 200
    assert resp_camp_route.headers["content-type"] == "application/pdf"
    assert resp_camp_route.content.startswith(b"%PDF-")

    # Hit direct campaign report endpoint: /api/campaigns/{camp_id}/reports/download
    resp_direct = client.get(f"/api/campaigns/{camp.id}/reports/download", headers=auth_headers)
    assert resp_direct.status_code == 200
    assert resp_direct.headers["content-type"] == "application/pdf"
    assert resp_direct.content.startswith(b"%PDF-")


def test_download_report_404_on_nonexistent_id(client, auth_headers):
    resp = client.get("/api/reports/scan/nonexistent-id-999", headers=auth_headers)
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()
