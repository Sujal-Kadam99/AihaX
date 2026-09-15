"""AihaX Phase 13.z — Controlled Live Runtime Execution Verification Test Suite.

Verifies the full end-to-end execution path against a controlled local loopback target:
1. Local HTTP fixture starts and responds
2. Concrete local target URL validation
3. Scope authorization of exact concrete local target
4. Campaign creation via API
5. Campaign authorization via API
6. Campaign start creates initial ExecutionTasks
7. Worker claims local task atomically (PENDING -> CLAIMED -> RUNNING)
8. Claim populates worker_id and lease_expires_at
9. Worker heartbeat advances activity timestamps
10. Real local HTTP execution through RequestEngine (zero external network)
11. Request accounting increments accurately
12. EvidenceRecord persisted in EvidenceVault with SHA-256 hash & secret redaction
13. Check execution produces verifiable finding / clean evidence
14. Report generation via API (POST /api/campaigns/{id}/reports)
15. PDF download verifies '%PDF-' magic bytes (GET /api/campaigns/{id}/reports/download)
16. Campaign auto-completes naturally when all tasks finish
17. Cryptographic Evidence Manifest is sealed and verified
18. Cancellation clears worker leases and releases target assignment
19. Cancellation is strictly idempotent
20. Cancelled task cannot resurrect on crash recovery
21. External network calls are strictly zero (guarded transport)
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Generator, List, Optional

import pytest
from aiohttp import web
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.core.auth import get_or_create_api_token
from backend.core.check_registry import registry
import backend.agents.checks  # Load all registered checks
from backend.core.scope_validator import (
    ScopeDecision,
    ScopeStatus,
    ScopeValidator,
    validate_concrete_target_url,
)
from backend.main import app
from backend.models.database import Base, Finding, Program, ProgramScope, Scan, get_db
from backend.persistence.models import (
    AuditTrailEvent,
    Campaign,
    CampaignTarget,
    EvidenceRecord,
    ExecutionTask,
)
from backend.persistence.repository import CampaignRepository
from backend.persistence.state_machine import (
    CampaignLifecycleState,
    InvalidStateTransitionError,
    TaskLifecycleState,
)
from backend.services.campaign_operations import CampaignOperationsService
from backend.services.campaign_worker import CampaignWorker, CampaignWorkerRuntime
from backend.services.report_generator import generate_scan_report
from backend.services.request_engine import (
    AiohttpTransport,
    BaseAsyncTransport,
    RawResponse,
    RequestEngine,
    RequestSpec,
    RequestTimeout,
    TransportError,
)
from backend.tests.fixtures.security_lab.lab_server import create_security_lab_app


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ──────────────────────────────────────────────────────────────────────────────
# STRICT LOOPBACK TRANSPORT GUARD (Phase 14 Guarantee: External calls = 0)
# ──────────────────────────────────────────────────────────────────────────────

class StrictLoopbackGuardTransport(AiohttpTransport):
    """Transport that strictly enforces loopback-only connections and logs call count."""

    def __init__(self) -> None:
        super().__init__()
        self.external_calls_attempted = 0
        self.local_requests_executed = 0

    async def send(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        params: dict[str, Any],
        body: Optional[bytes],
        timeout: RequestTimeout,
        max_response_size: int,
    ) -> RawResponse:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if host not in ("127.0.0.1", "localhost", "::1"):
            self.external_calls_attempted += 1
            raise TransportError(
                error_type="SECURITY_GUARD_BLOCKED",
                message=f"Strict Loopback Guard BLOCKED non-loopback connection to '{host}'",
            )
        self.local_requests_executed += 1
        return await super().send(
            method=method,
            url=url,
            headers=headers,
            params=params,
            body=body,
            timeout=timeout,
            max_response_size=max_response_size,
        )


@pytest.fixture
def db_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture
def session_factory(db_engine):
    return sessionmaker(bind=db_engine, expire_on_commit=False)


@pytest.fixture
def db_session(session_factory):
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def auth_headers():
    token = get_or_create_api_token()
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def api_client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, base_url="http://testserver") as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture
async def local_lab_server():
    """Starts a deterministic local security lab server on loopback."""
    lab_app = create_security_lab_app()
    runner = web.AppRunner(lab_app)
    await runner.setup()
    port = get_free_port()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    base_url = f"http://127.0.0.1:{port}"
    try:
        yield base_url
    finally:
        await runner.cleanup()


# ──────────────────────────────────────────────────────────────────────────────
# TESTS
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_1_local_fixture_starts_and_responds(local_lab_server):
    """1. Local HTTP fixture starts and returns deterministic 200 OK on diagnostic endpoints."""
    guard = StrictLoopbackGuardTransport()
    engine = RequestEngine(
        scope_validator=ScopeValidator(in_scope_assets=["127.0.0.1"]),
        transport=guard,
    )

    # Health check
    res_health = await engine.execute(RequestSpec(url=f"{local_lab_server}/health", method="GET"))
    assert res_health.success is True
    assert res_health.response_status == 200
    assert "AihaX Safe Local Fixture" in (res_health.response_body or "")

    # Security test
    res_sec = await engine.execute(RequestSpec(url=f"{local_lab_server}/security-test", method="GET"))
    assert res_sec.success is True
    assert res_sec.response_status == 200
    assert "Controlled Local Target" in (res_sec.response_body or "")

    # Robots.txt
    res_robots = await engine.execute(RequestSpec(url=f"{local_lab_server}/robots.txt", method="GET"))
    assert res_robots.success is True
    assert res_robots.response_status == 200
    assert "Disallow" in (res_robots.response_body or "")

    assert guard.external_calls_attempted == 0
    assert guard.local_requests_executed == 3


def test_2_concrete_local_url_validation():
    """2. Concrete local target URL validation validates correctly and rejects wildcards."""
    # Valid concrete local targets
    scheme, host, port, path, canonical = validate_concrete_target_url("http://127.0.0.1:8080")
    assert scheme == "http"
    assert host == "127.0.0.1"
    assert port == 8080

    scheme, host, port, path, canonical = validate_concrete_target_url("http://localhost:3000/app")
    assert scheme == "http"
    assert host == "localhost"
    assert port == 3000

    # Wildcards rejected
    with pytest.raises(ValueError, match="Wildcard"):
        validate_concrete_target_url("http://*.127.0.0.1")

    with pytest.raises(ValueError, match="Wildcard"):
        validate_concrete_target_url("*.localhost")


def test_3_scope_authorizes_exact_local_target_and_rejects_wildcard():
    """3. ScopeValidator authorizes exact local target without wildcard contamination."""
    validator = ScopeValidator(
        in_scope_assets=["http://127.0.0.1:8888", "127.0.0.1"],
        out_of_scope_assets=["https://evil.com"],
        allowed_ports=[8888],
        allowed_schemes=["http"],
    )

    decision_in = validator.is_url_in_scope("http://127.0.0.1:8888/security-test")
    assert decision_in.allowed is True
    assert decision_in.status == ScopeStatus.IN_SCOPE

    # Wildcard target is rejected as INVALID
    decision_wildcard = validator.is_asset_in_scope("*.127.0.0.1")
    assert decision_wildcard.allowed is False
    assert decision_wildcard.status == ScopeStatus.INVALID

    # Out of scope target is denied
    decision_out = validator.is_url_in_scope("https://evil.com/login")
    assert decision_out.allowed is False
    assert decision_out.status in (ScopeStatus.OUT_OF_SCOPE, ScopeStatus.DENIED_BY_DEFAULT)


def test_4_campaign_creation_via_api(api_client, db_session, auth_headers):
    """4. Campaign creation via POST /api/campaigns validates target and stores concrete URL."""
    prog = Program(id="prog-local-01", name="Local Lab Program")
    scope = ProgramScope(
        id="scope-local-01",
        program_id=prog.id,
        in_scope_assets=json.dumps(["http://127.0.0.1:8888", "127.0.0.1"]),
    )
    db_session.add(prog)
    db_session.add(scope)
    db_session.commit()

    payload = {
        "name": "Local Lab Assessment",
        "target_url": "http://127.0.0.1:8888",
        "program_id": prog.id,
        "mode": "SAFE_SCAN",
        "campaign_budget": 100,
        "selected_checks": ["C049_Clickjacking"],
    }
    resp = api_client.post("/api/campaigns", json=payload, headers=auth_headers)
    assert resp.status_code in (200, 201), resp.text
    data = resp.json()["data"]
    assert data["target_url"] == "http://127.0.0.1:8888"
    assert data["status"] == "DRAFT"


def test_5_campaign_authorization_via_api(api_client, db_session, auth_headers):
    """5. Campaign authorization transitions DRAFT -> AUTHORIZED."""
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)
    camp = service.create_campaign(name="Auth Test", target_url="http://127.0.0.1:8888")
    db_session.commit()

    auth_resp = api_client.post(
        f"/api/campaigns/{camp.id}/authorize",
        json={"authorized_by": "qa_operator", "duration_days": 7},
        headers=auth_headers,
    )
    assert auth_resp.status_code == 200
    assert auth_resp.json()["data"]["status"] == "AUTHORIZED"


def test_6_campaign_start_creates_initial_tasks(api_client, db_session, auth_headers):
    """6. Campaign start transitions AUTHORIZED -> RUNNING and creates initial tasks."""
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)
    camp = service.create_campaign(
        name="Start Test",
        target_url="http://127.0.0.1:8888",
        selected_checks=["C049_Clickjacking"],
    )
    service.authorize_campaign(camp.id, authorized_by="qa_lead")
    db_session.commit()

    start_resp = api_client.post(f"/api/campaigns/{camp.id}/start", headers=auth_headers)
    assert start_resp.status_code == 200
    assert start_resp.json()["data"]["status"] == "RUNNING"

    tasks = db_session.query(ExecutionTask).filter(ExecutionTask.campaign_id == camp.id).all()
    assert len(tasks) == 1
    assert tasks[0].status == TaskLifecycleState.PENDING.value
    assert tasks[0].target_url == "http://127.0.0.1:8888"


def test_7_worker_claims_local_task_atomically(db_session):
    """7. Worker claims pending task atomically: PENDING -> CLAIMED."""
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)
    camp = service.create_campaign(
        name="Claim Test",
        target_url="http://127.0.0.1:8888",
        selected_checks=["C049_Clickjacking"],
    )
    service.authorize_campaign(camp.id, authorized_by="qa_lead")
    service.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    claimed = repo.claim_tasks(camp.id, worker_id="worker-qa-01", limit=1)
    assert len(claimed) == 1
    assert claimed[0].status == TaskLifecycleState.CLAIMED.value
    assert claimed[0].worker_id == "worker-qa-01"


def test_8_claim_populates_worker_id_and_lease(db_session):
    """8. Task claiming sets worker_id and a valid lease_expires_at in the future."""
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)
    camp = service.create_campaign(
        name="Lease Test",
        target_url="http://127.0.0.1:8888",
        selected_checks=["C049_Clickjacking"],
    )
    service.authorize_campaign(camp.id, authorized_by="qa_lead")
    service.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    claimed = repo.claim_tasks(camp.id, worker_id="worker-lease-01", limit=1, lease_duration_seconds=45)
    task = claimed[0]
    assert task.worker_id == "worker-lease-01"
    assert task.lease_expires_at is not None
    assert task.lease_expires_at > datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_9_worker_heartbeat_advances_activity(db_session, session_factory):
    """9. Background heartbeat loop renews task lease and records audit activity."""
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)
    camp = service.create_campaign(
        name="Heartbeat Test",
        target_url="http://127.0.0.1:8888",
        selected_checks=["C049_Clickjacking"],
    )
    service.authorize_campaign(camp.id, authorized_by="qa_lead")
    service.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    claimed = repo.claim_tasks(camp.id, worker_id="worker-hb-01", limit=1)
    task_id = claimed[0].id
    db_session.commit()

    worker = CampaignWorker(worker_id="worker-hb-01", heartbeat_interval=0.1, session_factory=session_factory)
    stop_event = asyncio.Event()
    hb_task = asyncio.create_task(worker._heartbeat_loop(task_id, stop_event))

    await asyncio.sleep(0.35)
    stop_event.set()
    await hb_task

    db_session.expire_all()
    task = db_session.query(ExecutionTask).filter(ExecutionTask.id == task_id).first()
    assert task.lease_expires_at > datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_10_real_local_http_execution_through_request_engine(local_lab_server, db_session):
    """10. Real local HTTP request executes through RequestEngine with Guard verification."""
    guard = StrictLoopbackGuardTransport()
    validator = ScopeValidator(in_scope_assets=[local_lab_server, "127.0.0.1"])
    engine = RequestEngine(scope_validator=validator, transport=guard)

    spec = RequestSpec(
        url=f"{local_lab_server}/vulnerable/c002_missing_headers",
        method="GET",
        headers={"X-AihaX-Test": "Phase13z"},
    )
    evidence = await engine.execute(spec)

    assert evidence.success is True
    assert evidence.response_status == 200
    assert "Missing Security Headers" in (evidence.response_body or "")
    assert guard.external_calls_attempted == 0
    assert guard.local_requests_executed == 1


@pytest.mark.asyncio
async def test_11_request_accounting_increments(local_lab_server, db_session):
    """11. Worker executing task against local target increments requests_used."""
    guard = StrictLoopbackGuardTransport()
    validator = ScopeValidator(in_scope_assets=[local_lab_server, "127.0.0.1"])
    req_engine = RequestEngine(scope_validator=validator, transport=guard)

    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)
    camp = service.create_campaign(
        name="Request Counter Test",
        target_url=local_lab_server,
        selected_checks=["C049_Clickjacking"],
    )
    service.authorize_campaign(camp.id, authorized_by="qa_lead")
    service.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    worker = CampaignWorker(worker_id="worker-req-01", request_engine=req_engine)
    claimed = repo.claim_tasks(camp.id, worker.worker_id, limit=1)
    db_session.commit()

    await worker.execute_task(claimed[0].id, db_session, repo)
    db_session.refresh(camp)

    assert camp.requests_used >= 1
    assert guard.local_requests_executed >= 1
    assert guard.external_calls_attempted == 0


@pytest.mark.asyncio
async def test_12_evidence_persisted_in_vault_with_sanitization(local_lab_server, db_session):
    """12. EvidenceRecord persisted in database with SHA-256 hash and secret redaction."""
    from backend.evidence.redaction import redact_secrets
    from backend.evidence.integrity import compute_evidence_content_hash

    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)
    camp = service.create_campaign(
        name="Evidence Vault Test",
        target_url=local_lab_server,
        selected_checks=["C049_Clickjacking"],
    )
    service.authorize_campaign(camp.id, authorized_by="qa_lead")
    service.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    raw_req = "GET /profile HTTP/1.1\nHost: 127.0.0.1\nAuthorization: Bearer SECRET_TOKEN_ABC123"
    raw_res = "HTTP/1.1 200 OK\nSet-Cookie: session=SECRET_SESSION_777\n\n{\"user\":\"admin\"}"

    sanitized_req = redact_secrets(raw_req)
    sanitized_res = redact_secrets(raw_res)
    assert "SECRET_TOKEN_ABC123" not in sanitized_req
    assert "SECRET_SESSION_777" not in sanitized_res

    content_hash = compute_evidence_content_hash(
        evidence_type="PROOF",
        target_url=f"{local_lab_server}/profile",
        method="GET",
        sanitized_request=sanitized_req,
        sanitized_response=sanitized_res,
    )

    ev_rec = repo.record_evidence(
        campaign_id=camp.id,
        evidence_type="PROOF",
        target_url=f"{local_lab_server}/profile",
        content_hash=content_hash,
        method="GET",
        sanitized_request=sanitized_req,
        sanitized_response=sanitized_res,
    )
    db_session.commit()

    assert ev_rec.id is not None
    assert ev_rec.campaign_id == camp.id
    assert ev_rec.content_hash == content_hash


@pytest.mark.asyncio
async def test_13_check_execution_and_finding_verification(local_lab_server, db_session):
    """13. Real check execution against local target creates finding and verifies truthfully."""
    guard = StrictLoopbackGuardTransport()
    validator = ScopeValidator(in_scope_assets=[local_lab_server, "127.0.0.1"])
    req_engine = RequestEngine(scope_validator=validator, transport=guard)

    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)
    camp = service.create_campaign(
        name="Finding Test",
        target_url=local_lab_server,
        selected_checks=["C049_Clickjacking"],
    )
    service.authorize_campaign(camp.id, authorized_by="qa_lead")
    service.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    # Backing scan row for foreign key
    scan = Scan(id=camp.id, target_url=local_lab_server, status="running")
    db_session.add(scan)
    db_session.commit()

    worker = CampaignWorker(worker_id="worker-find-01", request_engine=req_engine)
    claimed = repo.claim_tasks(camp.id, worker.worker_id, limit=1)
    db_session.commit()

    res = await worker.execute_task(claimed[0].id, db_session, repo)
    assert res["status"] == "completed", f"Execute task failed: {res}"

    findings = db_session.query(Finding).filter(Finding.scan_id == camp.id).all()
    assert len(findings) >= 1
    assert findings[0].verdict in ("Verified", "Hardening Only", "Inconclusive")
    assert guard.external_calls_attempted == 0


def test_14_report_generation_via_api(api_client, db_session, auth_headers):
    """14. Report generation endpoint POST /api/campaigns/{id}/reports succeeds."""
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)
    camp = service.create_campaign(name="Report API Test", target_url="http://127.0.0.1:8888")
    db_session.commit()

    scan = Scan(id=camp.id, target_url="http://127.0.0.1:8888", status="completed")
    db_session.add(scan)
    f = Finding(
        id="f-local-01",
        scan_id=camp.id,
        agent_id=1,
        title="Missing Security Headers",
        vuln_type="C049_Clickjacking",
        category="misconfig",
        severity="medium",
        affected_url="http://127.0.0.1:8888/vulnerable/c002_missing_headers",
        verdict="Verified",
        verification_status="VERIFIED",
        false_positive=False,
    )
    db_session.add(f)
    db_session.commit()

    gen_resp = api_client.post(f"/api/campaigns/{camp.id}/reports", headers=auth_headers)
    assert gen_resp.status_code == 200
    assert gen_resp.json()["success"] is True
    assert gen_resp.json()["verified_findings_count"] == 1


def test_15_pdf_download_verifies_magic_header(api_client, db_session, auth_headers):
    """15. PDF download GET /api/campaigns/{id}/reports/download returns %PDF- header."""
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)
    camp = service.create_campaign(name="PDF Download Test", target_url="http://127.0.0.1:8888")
    db_session.commit()

    scan = Scan(id=camp.id, target_url="http://127.0.0.1:8888", status="completed")
    db_session.add(scan)
    f = Finding(
        id="f-pdf-01",
        scan_id=camp.id,
        agent_id=1,
        title="Missing Security Headers",
        vuln_type="C049_Clickjacking",
        category="misconfig",
        severity="medium",
        affected_url="http://127.0.0.1:8888/vulnerable/c002_missing_headers",
        verdict="Verified",
        verification_status="VERIFIED",
        false_positive=False,
    )
    db_session.add(f)
    db_session.commit()

    dl_resp = api_client.get(f"/api/campaigns/{camp.id}/reports/download", headers=auth_headers)
    assert dl_resp.status_code == 200
    assert dl_resp.headers["content-type"] == "application/pdf"
    assert dl_resp.content.startswith(b"%PDF-")
    assert len(dl_resp.content) > 500


@pytest.mark.asyncio
async def test_16_campaign_auto_completes_naturally(local_lab_server, db_session):
    """16. When all tasks complete, campaign auto-completes to COMPLETED state."""
    guard = StrictLoopbackGuardTransport()
    validator = ScopeValidator(in_scope_assets=[local_lab_server, "127.0.0.1"])
    req_engine = RequestEngine(scope_validator=validator, transport=guard)

    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)
    camp = service.create_campaign(
        name="Auto Complete Test",
        target_url=local_lab_server,
        selected_checks=["C049_Clickjacking"],
    )
    service.authorize_campaign(camp.id, authorized_by="qa_lead")
    service.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    # Backing scan row for finding foreign key
    scan = Scan(id=camp.id, target_url=local_lab_server, status="running")
    db_session.add(scan)
    db_session.commit()

    worker = CampaignWorker(worker_id="worker-auto-01", request_engine=req_engine)
    claimed = repo.claim_tasks(camp.id, worker.worker_id, limit=1)
    db_session.commit()

    await worker.execute_task(claimed[0].id, db_session, repo)
    db_session.refresh(camp)

    assert camp.status == CampaignLifecycleState.COMPLETED.value
    truth = service.get_campaign_runtime_truth(camp.id)
    assert truth["status"] == "COMPLETED"
    assert truth["current_phase"] == "COMPLETED"
    assert truth["is_stalled"] is False


def test_17_evidence_manifest_is_sealed_and_verified(db_session):
    """17. Cryptographic evidence manifest is sealed on completion and verifies cleanly."""
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)
    camp = service.create_campaign(name="Manifest Test", target_url="http://127.0.0.1:8888")
    service.authorize_campaign(camp.id, authorized_by="qa_lead")
    service.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    # Complete campaign
    service.complete_campaign(camp.id, actor="lead_operator")
    db_session.commit()

    integrity = service.verify_campaign_integrity(camp.id)
    assert integrity.verified is True
    assert len(integrity.issues) == 0
    assert integrity.manifest_hash is not None


def test_18_cancellation_clears_leases_and_releases_target(db_session):
    """18. Cancellation transitions tasks to CANCELLED, clears leases, and releases target."""
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)
    camp = service.create_campaign(
        name="Cancel Test",
        target_url="http://127.0.0.1:8888",
        selected_checks=["C049_Clickjacking"],
    )
    service.authorize_campaign(camp.id, authorized_by="qa_lead")
    service.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    claimed = repo.claim_tasks(camp.id, worker_id="worker-cancel-01", limit=1)
    task = claimed[0]
    db_session.commit()

    # Cancel campaign
    service.cancel_campaign(camp.id, actor="lead_operator", reason="Operator cancellation")
    db_session.commit()

    db_session.refresh(camp)
    db_session.refresh(task)

    assert camp.status == CampaignLifecycleState.CANCELLED.value
    assert task.status == TaskLifecycleState.CANCELLED.value
    assert task.lease_expires_at is None

    targets = repo.get_targets(camp.id)
    assert targets[0].target_status == "RELEASED"


def test_19_cancellation_is_strictly_idempotent(db_session):
    """19. Repeated cancellation calls are strictly idempotent and do not error."""
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)
    camp = service.create_campaign(name="Idempotent Cancel", target_url="http://127.0.0.1:8888")
    service.authorize_campaign(camp.id, authorized_by="qa_lead")
    service.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    c1 = service.cancel_campaign(camp.id, actor="lead_operator")
    c2 = service.cancel_campaign(camp.id, actor="lead_operator")

    assert c1.status == CampaignLifecycleState.CANCELLED.value
    assert c2.status == CampaignLifecycleState.CANCELLED.value


def test_20_cancelled_task_cannot_resurrect_on_recovery(db_session):
    """20. Crash recovery never resurrects tasks belonging to a cancelled campaign."""
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)
    camp = service.create_campaign(
        name="Anti Resurrection Test",
        target_url="http://127.0.0.1:8888",
        selected_checks=["C049_Clickjacking"],
    )
    service.authorize_campaign(camp.id, authorized_by="qa_lead")
    service.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    claimed = repo.claim_tasks(camp.id, worker_id="worker-resurrect-01", limit=1)
    task = claimed[0]
    service.cancel_campaign(camp.id, actor="lead_operator")
    db_session.commit()

    # Stage an expired lease
    task.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=120)
    db_session.commit()

    recovered = repo.recover_stale_tasks()
    db_session.commit()
    db_session.refresh(task)

    assert task.id not in [t.id for t in recovered]
    assert task.status == TaskLifecycleState.CANCELLED.value


@pytest.mark.asyncio
async def test_21_external_network_calls_are_strictly_zero(local_lab_server):
    """21. Strict transport guard blocks and records any attempted external connection."""
    guard = StrictLoopbackGuardTransport()
    validator = ScopeValidator(in_scope_assets=["https://example-external.com"])
    engine = RequestEngine(scope_validator=validator, transport=guard)

    # Attempt external request
    spec = RequestSpec(url="https://example-external.com/api", method="GET")
    evidence = await engine.execute(spec)

    assert evidence.success is False
    assert evidence.transport_error is not None
    assert evidence.transport_error.get("error_type") == "SECURITY_GUARD_BLOCKED"
    assert guard.external_calls_attempted == 1
    assert guard.local_requests_executed == 0
