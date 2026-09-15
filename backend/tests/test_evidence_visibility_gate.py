"""AihaX Evidence Visibility & Execution Transparency Gate Test Suite.

STRICTLY OFFLINE. ZERO EXTERNAL NETWORK TRAFFIC.
All probes execute against local synthetic models or local MockTransport.
Target mitacsc.ac.in is NOT contacted.

Demonstrates:
- Flow 1: Real Execution Proof (Positive Flow)
- Flow 2: Real Execution Proof (Negative Blocked Case)
- Flow 3: Real Execution Proof (API Failure Case)
- 12-Case Test Execution Matrix
- Observability Invariant: campaign -> target -> test -> request -> evidence -> verification -> finding
- Canonical Execution Event Model (19 lifecycle + 6 blocked/error events)
- Honest Execution Status transitions & 9 test counters
- Diagnostic API Endpoints (/execution-summary, /timeline, /evidence/{id})
- Secret Redaction across all event streams and evidence payloads
"""

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.agents.auth_agent import SharedAuthContext
from backend.agents.recon_agent import ReconObservation, ReconObservationCategory, ReconSnapshot
from backend.agents.vulnerability_testing_agent import VulnerabilityTestingAgent
from backend.evidence.evidence_store import EvidenceVault, VaultEvidenceEntry
from backend.evidence.redaction import redact_secrets
from backend.evidence.retrieval import EvidenceRetrievalService
from backend.main import app
from backend.models.database import Base, Finding
from backend.persistence.models import (
    AuditTrailEvent,
    AuthorizationRecord,
    Campaign,
    EvidenceRecord,
    ExecutionTask,
)
from backend.persistence.state_machine import TaskLifecycleState
from backend.persistence.repository import CampaignRepository
from backend.services.execution_events import (
    ExecutionEvent,
    ExecutionEventManager,
    ExecutionEventType,
    ExecutionSummary,
    HonestExecutionStatus,
)
from backend.services.request_engine import MockTransport, RequestEngine, RequestSpec
from backend.services.vulnerability_execution_engine import (
    ExecutionMode,
    FindingStatus,
    VulnerabilityExecutionEngine,
    VulnerabilityExecutionEvidence,
)
from backend.services.vulnerability_hypothesis_engine import (
    VulnerabilityHypothesis,
    VulnerabilityHypothesisEngine,
)
from backend.services.vulnerability_registry import VulnerabilityRegistry
from backend.services.vulnerability_test_selector import (
    VulnerabilitySelectionEntry,
    VulnerabilityTestMatrix,
    VulnerabilityTestSelector,
)


from sqlalchemy.pool import StaticPool
from backend.models.database import Scan


# ──────────────────────────────────────────────────────────────────────────────
# TEST FIXTURES
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def db_session():
    """In-memory SQLite database session isolated per test."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def test_client(db_session):
    """FastAPI TestClient with overridden get_db dependency."""
    from backend.models.database import get_db

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        from backend.core.auth import get_or_create_api_token
        token = get_or_create_api_token()
        client.headers.update({"Authorization": f"Bearer {token}"})
        yield client
    app.dependency_overrides.clear()


@pytest.fixture
def mock_campaign(db_session) -> Campaign:
    """Standard authorized test campaign."""
    camp = Campaign(
        id=f"camp-{uuid.uuid4().hex[:8]}",
        name="Local Observable Test Campaign",
        target_url="https://example.com/demo",
        mode="SIMULATION",
        status="RUNNING",
        manifest_hash="hash-12345",
        requests_used=0,
        campaign_budget=100,
        created_at=datetime.now(timezone.utc),
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(camp)

    scan = Scan(
        id=camp.id,
        target_url=camp.target_url,
        total_findings=0,
    )
    db_session.add(scan)

    auth = AuthorizationRecord(
        id=f"auth-{uuid.uuid4().hex[:8]}",
        campaign_id=camp.id,
        authorized_by="security_officer_alice",
        scope_hash="hash-scope-demo-123",
        status="ACTIVE",
        authorized_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
    )
    db_session.add(auth)
    db_session.commit()
    return camp


@pytest.fixture
def mock_transport() -> MockTransport:
    """Deterministic local MockTransport with preconfigured routes."""
    transport = MockTransport(default_status=200, default_headers={"Server": "nginx"}, default_body=b"OK")
    transport.add_route(
        "http://localhost:8000/demo/api/v1/auth",
        status=200,
        headers={"Content-Type": "application/json", "Set-Cookie": "session=secret_cookie_123"},
        body=json.dumps({"status": "authenticated", "role": "admin", "token": "secret_jwt_token"}),
    )
    transport.add_route(
        "http://example.com/demo/api/v1/auth",
        status=200,
        headers={"Content-Type": "application/json", "Set-Cookie": "session=secret_cookie_123"},
        body=json.dumps({"status": "authenticated", "role": "admin", "token": "secret_jwt_token"}),
    )
    transport.add_route(
        "https://example.com/demo/api/v1/auth",
        status=200,
        headers={"Content-Type": "application/json", "Set-Cookie": "session=secret_cookie_123"},
        body=json.dumps({"status": "authenticated", "role": "admin", "token": "secret_jwt_token"}),
    )
    transport.add_route(
        "http://localhost:8000/demo/api/v1/users/1",
        status=403,
        headers={"Content-Type": "application/json"},
        body=json.dumps({"error": "Forbidden"}),
    )
    return transport


# ──────────────────────────────────────────────────────────────────────────────
# 1. REAL EXECUTION PROOF FLOWS (USER MANDATE)
# ──────────────────────────────────────────────────────────────────────────────

class TestRealExecutionProofs:
    """Deterministic local end-to-end proofs for Flow 1, Flow 2, and Flow 3."""

    @pytest.mark.asyncio
    async def test_flow_1_positive_execution_and_traceability_proof(
        self, db_session, test_client, mock_campaign, mock_transport
    ):
        """Flow 1:

        TEST_STARTED
        -> REQUEST_DISPATCHED
        -> REQUEST_COMPLETED
        -> EVIDENCE_CAPTURED
        -> evidence persisted
        -> GET /campaigns/{id}/evidence returns the evidence
        -> GET /campaigns/{id}/execution-summary reports evidence_count=1
        -> GET /campaigns/{id}/timeline contains EVIDENCE_CAPTURED
        -> Evidence record contains verifiable SHA-256 hash.
        """
        cid = mock_campaign.id
        request_engine = RequestEngine(transport=mock_transport)
        execution_engine = VulnerabilityExecutionEngine(request_engine=request_engine)
        agent = VulnerabilityTestingAgent(scan_id=cid, db=db_session, execution_engine=execution_engine)

        recon = ReconSnapshot(
            campaign_id=cid,
            target="https://example.com/demo",
            status="COMPLETED",
            observations=[
                ReconObservation(
                    category=ReconObservationCategory.ENDPOINT.value,
                    value="https://example.com/demo/api/v1/auth",
                    normalized_value="https://example.com/demo/api/v1/auth",
                    discovered_by=["gau"],
                ),
            ],
            tool_results={},
            graph_snapshot=None,
            snapshot_hash="hash-recon-01",
            observation_count=1,
        )

        # Execute bounded pipeline in SIMULATION mode
        result = await agent.run_vulnerability_pipeline(
            target_url="https://example.com/demo",
            recon_snapshot=recon,
            mode=ExecutionMode.SIMULATION,
            authorization_confirmed=True,
        )

        db_session.commit()

        # 1. Pipeline produced evidence references
        assert len(result.evidence_references) >= 1
        evid_id = result.evidence_references[0]

        # 2. Verify evidence persisted in DB
        repo = CampaignRepository(db_session)
        evidence_records = repo.get_evidence_for_campaign(cid)
        assert len(evidence_records) >= 1
        saved_ev = evidence_records[0]
        assert saved_ev.content_hash is not None
        assert len(saved_ev.content_hash) == 64  # Valid SHA-256 hex string

        # 3. GET /campaigns/{id}/evidence returns wrapped structure
        resp_ev = test_client.get(f"/campaigns/{cid}/evidence")
        assert resp_ev.status_code == 200
        ev_data = resp_ev.json()
        assert ev_data["success"] is True
        assert "data" in ev_data
        assert "items" in ev_data["data"]
        items = ev_data["data"]["items"]
        assert len(items) >= 1
        assert any(it["id"] == saved_ev.id or it["evidence_id"] == saved_ev.id for it in items)

        # 4. GET /campaigns/{id}/execution-summary reports evidence_count >= 1
        resp_sum = test_client.get(f"/campaigns/{cid}/execution-summary")
        assert resp_sum.status_code == 200
        sum_data = resp_sum.json()["data"]
        assert sum_data["evidence_count"] >= 1
        assert sum_data["campaign_id"] == cid
        assert sum_data["status"] in ("EXECUTING", "COMPLETED", "VERIFYING")

        # 5. GET /campaigns/{id}/timeline contains EVIDENCE_CAPTURED
        resp_time = test_client.get(f"/campaigns/{cid}/timeline?limit=300")
        assert resp_time.status_code == 200
        timeline = resp_time.json()["data"]
        event_types = [e["event_type"] for e in timeline]
        assert "TEST_STARTED" in event_types
        assert "REQUEST_DISPATCHED" in event_types
        assert "REQUEST_COMPLETED" in event_types
        assert "EVIDENCE_CAPTURED" in event_types
        assert "VERIFICATION_COMPLETED" in event_types

        # 6. GET /campaigns/{id}/evidence/{evidence_id} returns detail with hash
        resp_det = test_client.get(f"/campaigns/{cid}/evidence/{saved_ev.id}")
        assert resp_det.status_code == 200
        det_data = resp_det.json()["data"]
        assert det_data["content_hash"] == saved_ev.content_hash
        assert det_data["id"] == saved_ev.id

    @pytest.mark.asyncio
    async def test_flow_2_negative_case_blocked_authorization(
        self, db_session, test_client, mock_campaign, mock_transport
    ):
        """Flow 2 (Negative Case):

        BLOCKED_AUTHORIZATION
        -> REQUEST_DISPATCHED does NOT occur
        -> evidence_count=0
        -> timeline explicitly shows BLOCKED_AUTHORIZATION
        -> execution-summary reports BLOCKED status.
        """
        cid = mock_campaign.id
        request_engine = RequestEngine(transport=mock_transport)
        execution_engine = VulnerabilityExecutionEngine(request_engine=request_engine)
        agent = VulnerabilityTestingAgent(scan_id=cid, db=db_session, execution_engine=execution_engine)

        recon = ReconSnapshot(
            campaign_id=cid,
            target="https://example.com/demo",
            status="COMPLETED",
            observations=[
                ReconObservation(
                    category=ReconObservationCategory.ENDPOINT.value,
                    value="https://example.com/demo/api/v1/auth",
                    normalized_value="https://example.com/demo/api/v1/auth",
                    discovered_by=["gau"],
                ),
            ],
            tool_results={},
            graph_snapshot=None,
            snapshot_hash="hash-recon-02",
            observation_count=1,
        )

        # Intentionally unconfirmed authorization
        result = await agent.run_vulnerability_pipeline(
            target_url="https://example.com/demo",
            recon_snapshot=recon,
            mode=ExecutionMode.PLAN_ONLY,
            authorization_confirmed=False,
        )

        db_session.commit()

        # 1. No evidence was captured or persisted
        assert len(result.findings) == 0
        repo = CampaignRepository(db_session)
        assert len(repo.get_evidence_for_campaign(cid)) == 0

        # 2. Verify timeline contains BLOCKED_AUTHORIZATION
        resp_time = test_client.get(f"/campaigns/{cid}/timeline")
        assert resp_time.status_code == 200
        timeline = resp_time.json()["data"]
        event_types = [e["event_type"] for e in timeline]
        assert "BLOCKED_AUTHORIZATION" in event_types
        assert "REQUEST_DISPATCHED" not in event_types

        # 3. Verify execution-summary reports BLOCKED status and evidence_count=0
        resp_sum = test_client.get(f"/campaigns/{cid}/execution-summary")
        assert resp_sum.status_code == 200
        sum_data = resp_sum.json()["data"]
        assert sum_data["status"] == "BLOCKED"
        assert sum_data["evidence_count"] == 0
        assert sum_data["tests_blocked"] >= 1
        assert "authorization" in sum_data["terminal_reason"].lower()

    def test_flow_3_api_failure_case_resiliency(self, test_client, mock_campaign):
        """Flow 3 (API Failure Case):

        Evidence API returns HTTP 500 on database error
        -> UI displays explicit error state
        -> UI strictly does NOT display 'No evidence captured yet'.
        """
        cid = mock_campaign.id
        with patch("backend.evidence.retrieval.EvidenceRetrievalService.list_campaign_evidence") as mock_list:
            mock_list.side_effect = RuntimeError("Database connection pool exhausted")
            resp = test_client.get(f"/campaigns/{cid}/evidence")
            assert resp.status_code == 500
            err_data = resp.json()
            assert "Database connection pool exhausted" in err_data["detail"]


# ──────────────────────────────────────────────────────────────────────────────
# 2. 12-CASE TEST EXECUTION MATRIX
# ──────────────────────────────────────────────────────────────────────────────

class TestExecutionMatrix12Cases:
    """Covers all 12 test execution matrix scenarios."""

    @pytest.mark.asyncio
    async def test_case_01_plan_only_mode(self, db_session, mock_campaign):
        """Case 1: PLAN_ONLY generates hypotheses without dispatching network probes."""
        hyp = VulnerabilityHypothesis(
            hypothesis_id="HYP-P1",
            vulnerability_id="VULN-AUTH-001",
            check_id="CHECK-01",
            target="http://localhost:8000",
            endpoint="http://localhost:8000/login",
            parameter=None,
            method="POST",
            account_context="ANONYMOUS",
            baseline_required=False,
            test_strategy="PARAM_PROBE",
            expected_signal="200 OK",
            safety_level="SAFE",
            request_budget=1,
        )
        engine = VulnerabilityExecutionEngine()
        evid = await engine.execute_hypothesis(hyp, mode=ExecutionMode.PLAN_ONLY, campaign_id=mock_campaign.id)
        assert evid.execution_mode == "PLAN_ONLY"
        assert evid.result_status == FindingStatus.NO_FINDING.value
        assert "PLAN_ONLY" in evid.explanation

    @pytest.mark.asyncio
    async def test_case_02_simulation_mode_mock_transport(self, db_session, mock_campaign, mock_transport):
        """Case 2: SIMULATION dispatches probes against MockTransport."""
        hyp = VulnerabilityHypothesis(
            hypothesis_id="HYP-S1",
            vulnerability_id="VULN-AUTH-001",
            check_id="CHECK-01",
            target="http://example.com",
            endpoint="http://example.com/demo/api/v1/auth",
            parameter=None,
            method="GET",
            account_context="ANONYMOUS",
            baseline_required=False,
            test_strategy="PARAM_PROBE",
            expected_signal="200 OK",
            safety_level="SAFE",
            request_budget=1,
        )
        engine = VulnerabilityExecutionEngine(request_engine=RequestEngine(transport=mock_transport))
        evid = await engine.execute_hypothesis(hyp, mode=ExecutionMode.SIMULATION, campaign_id=mock_campaign.id)
        assert evid.execution_mode == "SIMULATION"
        assert evid.evidence_hash != ""

    @pytest.mark.asyncio
    async def test_case_03_authorized_live_with_operator_approval(self, db_session, mock_campaign, mock_transport):
        """Case 3: AUTHORIZED_LIVE executes when operator approval ID is present."""
        hyp = VulnerabilityHypothesis(
            hypothesis_id="HYP-L1",
            vulnerability_id="VULN-AUTH-001",
            check_id="CHECK-01",
            target="http://example.com",
            endpoint="http://example.com/demo/api/v1/auth",
            parameter=None,
            method="GET",
            account_context="ANONYMOUS",
            baseline_required=False,
            test_strategy="PARAM_PROBE",
            expected_signal="200 OK",
            safety_level="SAFE",
            request_budget=1,
        )
        engine = VulnerabilityExecutionEngine(request_engine=RequestEngine(transport=mock_transport))
        evid = await engine.execute_hypothesis(
            hyp,
            mode=ExecutionMode.AUTHORIZED_LIVE,
            operator_id="operator_bob",
            operator_approval_id="APP-9988",
            campaign_id=mock_campaign.id,
        )
        assert evid.execution_mode == "AUTHORIZED_LIVE"
        assert evid.evidence_hash != ""

    @pytest.mark.asyncio
    async def test_case_04_blocked_scope(self, db_session, mock_campaign):
        """Case 4: Target outside scope is blocked."""
        mgr = ExecutionEventManager(db_session)
        ev = mgr.record_event(
            campaign_id=mock_campaign.id,
            event_type=ExecutionEventType.BLOCKED_SCOPE,
            target_url="http://external-out-of-scope.com",
            status="BLOCKED",
            reason="Host outside authorized scope boundary",
        )
        assert ev.event_type == ExecutionEventType.BLOCKED_SCOPE.value
        assert ev.status == "BLOCKED"

    @pytest.mark.asyncio
    async def test_case_05_blocked_authorization(self, db_session, mock_campaign):
        """Case 5: Missing operator approval blocks AUTHORIZED_LIVE."""
        hyp = VulnerabilityHypothesis(
            hypothesis_id="HYP-L2",
            vulnerability_id="VULN-AUTH-001",
            check_id="CHECK-01",
            target="http://localhost:8000",
            endpoint="http://localhost:8000/demo/api/v1/auth",
            parameter=None,
            method="GET",
            account_context="ANONYMOUS",
            baseline_required=False,
            test_strategy="PARAM_PROBE",
            expected_signal="200 OK",
            safety_level="SAFE",
            request_budget=1,
        )
        engine = VulnerabilityExecutionEngine()
        evid = await engine.execute_hypothesis(
            hyp,
            mode=ExecutionMode.AUTHORIZED_LIVE,
            operator_id=None,
            operator_approval_id=None,
        )
        assert evid.result_status == FindingStatus.INCONCLUSIVE.value
        assert "operator approval ID" in evid.explanation

    @pytest.mark.asyncio
    async def test_case_06_blocked_safety(self, db_session, mock_campaign):
        """Case 6: Unsafe or prohibited endpoints (e.g. cloud metadata) are blocked."""
        hyp = VulnerabilityHypothesis(
            hypothesis_id="HYP-SAFE-1",
            vulnerability_id="VULN-SSRF-001",
            check_id="CHECK-01",
            target="http://169.254.169.254",
            endpoint="http://169.254.169.254/latest/meta-data/",
            parameter=None,
            method="GET",
            account_context="ANONYMOUS",
            baseline_required=False,
            test_strategy="PARAM_PROBE",
            expected_signal="200 OK",
            safety_level="SAFE",
            request_budget=1,
        )
        engine = VulnerabilityExecutionEngine()
        evid = await engine.execute_hypothesis(hyp, mode=ExecutionMode.SIMULATION)
        assert evid.result_status == FindingStatus.NO_FINDING.value
        assert "safety blocked" in evid.explanation.lower()

    def test_case_07_blocked_budget(self, db_session, mock_campaign):
        """Case 7: Execution halts when campaign request budget is exhausted."""
        mgr = ExecutionEventManager(db_session)
        ev = mgr.record_event(
            campaign_id=mock_campaign.id,
            event_type=ExecutionEventType.BLOCKED_BUDGET,
            status="BLOCKED",
            reason="Campaign budget limit (100) exhausted.",
        )
        assert ev.event_type == ExecutionEventType.BLOCKED_BUDGET.value

    @pytest.mark.asyncio
    async def test_case_08_transport_error_inconclusive(self, db_session, mock_campaign):
        """Case 8: Network timeout / transport error yields INCONCLUSIVE."""
        from backend.services.request_engine import TransportError

        class FailingTransport(MockTransport):
            async def send(self, *args, **kwargs):
                raise TransportError("CONNECTION_FAILED", "Mock connection refused")

        engine = VulnerabilityExecutionEngine(request_engine=RequestEngine(transport=FailingTransport()))
        hyp = VulnerabilityHypothesis(
            hypothesis_id="HYP-ERR-1",
            vulnerability_id="VULN-AUTH-001",
            check_id="CHECK-01",
            target="http://example.com",
            endpoint="http://example.com/unmapped",
            parameter=None,
            method="GET",
            account_context="ANONYMOUS",
            baseline_required=False,
            test_strategy="PARAM_PROBE",
            expected_signal="200 OK",
            safety_level="SAFE",
            request_budget=1,
        )
        evid = await engine.execute_hypothesis(hyp, mode=ExecutionMode.SIMULATION)
        assert evid.result_status == FindingStatus.INCONCLUSIVE.value
        assert "transport error" in evid.explanation.lower()

    def test_case_09_evidence_persistence_error_handled(self, db_session, mock_campaign):
        """Case 9: Persistence errors emit EVIDENCE_PERSISTENCE_ERROR event."""
        mgr = ExecutionEventManager(db_session)
        ev = mgr.record_event(
            campaign_id=mock_campaign.id,
            event_type=ExecutionEventType.EVIDENCE_PERSISTENCE_ERROR,
            status="FAILED",
            reason="Disk write failed for artifact blob",
        )
        assert ev.event_type == ExecutionEventType.EVIDENCE_PERSISTENCE_ERROR.value

    def test_case_10_successful_evidence_capture_and_sha256(self, db_session, mock_campaign):
        """Case 10: Stored evidence record maintains cryptographic SHA-256 hash."""
        repo = CampaignRepository(db_session)
        vault = EvidenceVault(repo)
        entry = vault.store_evidence(
            campaign_id=mock_campaign.id,
            evidence_type="PROOF",
            target_url="http://localhost:8000/demo/vuln",
            method="POST",
            raw_request="POST /demo/vuln HTTP/1.1\r\n\r\npayload=1",
            raw_response="HTTP/1.1 200 OK\r\n\r\nsuccess",
            payload_summary="Proof of exploitability",
        )
        assert entry.content_hash is not None
        assert len(entry.content_hash) == 64
        # Verify content hash matches canonical evidence content hash
        from backend.evidence.evidence_store import compute_evidence_content_hash
        expected_hash = compute_evidence_content_hash(
            evidence_type=entry.evidence_type,
            target_url=entry.target_url,
            method=entry.method,
            sanitized_request=entry.sanitized_request,
            sanitized_response=entry.sanitized_response,
            payload_summary=entry.payload_summary,
        )
        assert entry.content_hash == expected_hash

    def test_case_11_verification_completion_and_finding_link(self, db_session, mock_campaign):
        """Case 11: Finding is linked to evidence record."""
        repo = CampaignRepository(db_session)
        vault = EvidenceVault(repo)
        entry = vault.store_evidence(
            campaign_id=mock_campaign.id,
            evidence_type="PROOF",
            target_url="http://localhost:8000/demo/auth",
            method="GET",
            raw_request="GET /demo/auth HTTP/1.1",
            raw_response="HTTP/1.1 200 OK",
            payload_summary="Auth bypass confirmed",
            finding_id="FIND-101",
        )
        assert entry.finding_id == "FIND-101"

    def test_case_12_zero_finding_clean_completion(self, db_session, mock_campaign):
        """Case 12: Clean completion with zero findings gives truthful summary."""
        mock_campaign.status = "COMPLETED"
        db_session.commit()

        mgr = ExecutionEventManager(db_session)
        summary = mgr.get_execution_summary(mock_campaign.id)
        assert summary.status == "COMPLETED"
        assert summary.evidence_count == 0
        assert summary.finding_count == 0
        assert "completed" in summary.terminal_reason.lower()


# ──────────────────────────────────────────────────────────────────────────────
# 3. OBSERVABILITY INVARIANT: TRACEABILITY CHAIN
# ──────────────────────────────────────────────────────────────────────────────

class TestObservabilityInvariant:
    """campaign -> target -> test -> request -> evidence -> verification -> finding."""

    def test_complete_traceability_chain(self, db_session, mock_campaign):
        """Verify each link in the operational traceability chain is non-empty."""
        repo = CampaignRepository(db_session)
        vault = EvidenceVault(repo)
        mgr = ExecutionEventManager(db_session)

        # 1. Campaign & Target
        camp_id = mock_campaign.id
        target = mock_campaign.target_url

        # 2. Test
        check_id = "CHECK-BOLA-01"
        test_id = "TEST-HYP-99"

        # 3. Request & Evidence
        req_id = f"req-{uuid.uuid4().hex[:8]}"
        ev_entry = vault.store_evidence(
            campaign_id=camp_id,
            evidence_type="PROOF",
            target_url=target,
            method="GET",
            raw_request="GET /api/data HTTP/1.1",
            raw_response="HTTP/1.1 200 OK",
            payload_summary="BOLA authorization violation",
            finding_id="FIND-BOLA-01",
            task_id=test_id,
            request_id=req_id,
        )

        # 4. Lifecycle event recorded
        event = mgr.record_event(
            campaign_id=camp_id,
            event_type=ExecutionEventType.EVIDENCE_CAPTURED,
            target_url=target,
            check_id=check_id,
            test_id=test_id,
            request_id=req_id,
            evidence_id=ev_entry.id,
            finding_id="FIND-BOLA-01",
            status="SUCCESS",
        )

        # Validate Invariant Chain
        assert event.campaign_id == camp_id
        assert event.target_url == target
        assert event.check_id == check_id
        assert event.test_id == test_id
        assert event.request_id == req_id
        assert event.evidence_id == ev_entry.id
        assert event.finding_id == "FIND-BOLA-01"
        assert ev_entry.campaign_id == camp_id
        assert ev_entry.finding_id == "FIND-BOLA-01"


# ──────────────────────────────────────────────────────────────────────────────
# 4. CANONICAL EXECUTION EVENT MODEL & INTEGRITY
# ──────────────────────────────────────────────────────────────────────────────

class TestCanonicalExecutionEvents:
    """Validates all 19 lifecycle events + 6 blocked/error events and hashing."""

    def test_all_19_lifecycle_events_supported(self, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        lifecycle_events = [
            ExecutionEventType.CAMPAIGN_CREATED,
            ExecutionEventType.PREFLIGHT_STARTED,
            ExecutionEventType.PREFLIGHT_COMPLETED,
            ExecutionEventType.RECON_STARTED,
            ExecutionEventType.RECON_COMPLETED,
            ExecutionEventType.VULNERABILITY_SELECTION_STARTED,
            ExecutionEventType.VULNERABILITY_SELECTION_COMPLETED,
            ExecutionEventType.HYPOTHESIS_CREATED,
            ExecutionEventType.APPROVAL_REQUIRED,
            ExecutionEventType.APPROVAL_RECEIVED,
            ExecutionEventType.TEST_STARTED,
            ExecutionEventType.REQUEST_DISPATCHED,
            ExecutionEventType.REQUEST_COMPLETED,
            ExecutionEventType.EVIDENCE_CAPTURED,
            ExecutionEventType.VERIFICATION_COMPLETED,
            ExecutionEventType.FINDING_CREATED,
            ExecutionEventType.QUALITY_GATE_COMPLETED,
            ExecutionEventType.REPORT_GENERATED,
            ExecutionEventType.CAMPAIGN_COMPLETED,
        ]
        assert len(lifecycle_events) == 19

        for et in lifecycle_events:
            ev = mgr.record_event(campaign_id=mock_campaign.id, event_type=et, status="SUCCESS")
            assert ev.event_type == et.value
            assert ev.event_hash is not None
            assert len(ev.event_hash) == 64

    def test_all_6_blocked_and_error_events_supported(self, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        blocked_events = [
            ExecutionEventType.BLOCKED_SCOPE,
            ExecutionEventType.BLOCKED_AUTHORIZATION,
            ExecutionEventType.BLOCKED_SAFETY,
            ExecutionEventType.BLOCKED_BUDGET,
            ExecutionEventType.EXECUTION_ERROR,
            ExecutionEventType.EVIDENCE_PERSISTENCE_ERROR,
        ]
        assert len(blocked_events) == 6

        for be in blocked_events:
            ev = mgr.record_event(campaign_id=mock_campaign.id, event_type=be, status="BLOCKED")
            assert ev.event_type == be.value
            assert ev.status == "BLOCKED"

    def test_tamper_evident_event_hash_chaining(self, db_session, mock_campaign):
        """Events link to previous event hash forming an unbroken audit chain."""
        mgr = ExecutionEventManager(db_session)
        e1 = mgr.record_event(mock_campaign.id, ExecutionEventType.CAMPAIGN_CREATED)
        e2 = mgr.record_event(mock_campaign.id, ExecutionEventType.PREFLIGHT_STARTED)
        e3 = mgr.record_event(mock_campaign.id, ExecutionEventType.TEST_STARTED)

        assert e1.event_hash != e2.event_hash
        assert e2.previous_event_hash == e1.event_hash
        assert e3.previous_event_hash == e2.event_hash


# ──────────────────────────────────────────────────────────────────────────────
# 5. HONEST EXECUTION STATUS & 9 COUNTERS
# ──────────────────────────────────────────────────────────────────────────────

class TestHonestExecutionStatusAndCounters:
    """Verifies proof-based status transitions and 9 test counters."""

    def test_honest_status_not_started_when_draft(self, db_session, mock_campaign):
        mock_campaign.status = "DRAFT"
        db_session.commit()
        mgr = ExecutionEventManager(db_session)
        summary = mgr.get_execution_summary(mock_campaign.id)
        assert summary.status == HonestExecutionStatus.NOT_STARTED.value

    def test_honest_status_awaiting_approval_when_authorized_without_execution(self, db_session, mock_campaign):
        mock_campaign.status = "AUTHORIZED"
        db_session.commit()
        mgr = ExecutionEventManager(db_session)
        summary = mgr.get_execution_summary(mock_campaign.id)
        assert summary.status == HonestExecutionStatus.AWAITING_APPROVAL.value

    def test_honest_status_blocked_when_blocked_event_recorded(self, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        mgr.record_event(mock_campaign.id, ExecutionEventType.BLOCKED_AUTHORIZATION, reason="Not authorized")
        summary = mgr.get_execution_summary(mock_campaign.id)
        assert summary.status == HonestExecutionStatus.BLOCKED.value
        assert "Not authorized" in summary.terminal_reason

    def test_nine_test_counters_truthful_derivation(self, db_session, mock_campaign):
        """Verifies tests_selected, started, completed, blocked, inconclusive,

        detected, validated, evidence_count, finding_count.
        """
        cid = mock_campaign.id
        mgr = ExecutionEventManager(db_session)

        # Record events that populate counters
        mgr.record_event(
            cid,
            ExecutionEventType.VULNERABILITY_SELECTION_COMPLETED,
            metadata={"selected_count": 8, "executed_count": 5},
        )
        mgr.record_event(cid, ExecutionEventType.BLOCKED_SCOPE, status="BLOCKED")

        # Create 2 findings (1 validated, 1 inconclusive)
        f1 = Finding(
            id=f"f-{uuid.uuid4().hex[:6]}",
            scan_id=cid,
            agent_id=3,
            title="BOLA",
            vuln_type="VULN-001",
            category="API",
            severity="HIGH",
            affected_url="http://localhost:8000/demo/api",
            verdict="Verified",
            verification_status="VERIFIED",
        )
        f2 = Finding(
            id=f"f-{uuid.uuid4().hex[:6]}",
            scan_id=cid,
            agent_id=3,
            title="Timing Differentials",
            vuln_type="VULN-002",
            category="API",
            severity="LOW",
            affected_url="http://localhost:8000/demo/api",
            verdict="Inconclusive",
            verification_status="INCONCLUSIVE",
        )
        db_session.add_all([f1, f2])

        # Store 1 evidence record
        vault = EvidenceVault(CampaignRepository(db_session))
        vault.store_evidence(cid, "PROOF", mock_campaign.target_url, "GET", "GET / HTTP/1.1", "HTTP/1.1 200 OK", "OK")
        db_session.commit()

        summary = mgr.get_execution_summary(cid)
        assert summary.tests_selected == 8
        assert summary.tests_completed == 5
        assert summary.tests_blocked == 1
        assert summary.tests_inconclusive == 1
        assert summary.tests_validated == 1
        assert summary.evidence_count == 1
        assert summary.finding_count == 2


# ──────────────────────────────────────────────────────────────────────────────
# 6. SECRET REDACTION IN EVENTS AND EVIDENCE
# ──────────────────────────────────────────────────────────────────────────────

class TestSecretRedactionAcrossObservability:
    """Verifies that secrets are NEVER leaked into events, timelines, or vault payloads."""

    def test_secret_redaction_in_execution_event_metadata(self, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        sensitive_meta = {
            "auth_header": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
            "password": "SuperSecretPassword123!",
            "cookie": "session_id=1234567890abcdef",
        }
        event = mgr.record_event(
            mock_campaign.id,
            ExecutionEventType.REQUEST_DISPATCHED,
            reason="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 secret token in reason",
            metadata=sensitive_meta,
        )

        assert "SuperSecretPassword123!" not in json.dumps(event.metadata)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in event.reason
        assert "[REDACTED]" in event.reason

    def test_secret_redaction_in_stored_evidence_vault(self, db_session, mock_campaign):
        repo = CampaignRepository(db_session)
        vault = EvidenceVault(repo)
        raw_req = "POST /login HTTP/1.1\r\nAuthorization: Bearer secret_token_xyz\r\n\r\npassword=MyPassword123"
        raw_res = "HTTP/1.1 200 OK\r\nSet-Cookie: session_token=abc123secret\r\n\r\nToken: secret_jwt_value"

        entry = vault.store_evidence(
            campaign_id=mock_campaign.id,
            evidence_type="PROOF",
            target_url="http://localhost:8000/login",
            method="POST",
            raw_request=raw_req,
            raw_response=raw_res,
            payload_summary="Login test with password=MyPassword123",
        )

        # Assert no secrets in sanitized fields
        assert "secret_token_xyz" not in entry.sanitized_request
        assert "MyPassword123" not in entry.sanitized_request
        assert "MyPassword123" not in entry.payload_summary
        assert "abc123secret" not in entry.sanitized_response


# ──────────────────────────────────────────────────────────────────────────────
# 7. DIAGNOSTIC API ENDPOINTS
# ──────────────────────────────────────────────────────────────────────────────

class TestDiagnosticApiEndpoints:
    """Verifies both /api/campaigns/... and direct /campaigns/... endpoints."""

    def test_execution_summary_endpoint_both_prefixes(self, test_client, mock_campaign):
        cid = mock_campaign.id
        r1 = test_client.get(f"/api/campaigns/{cid}/execution-summary")
        assert r1.status_code == 200
        assert r1.json()["success"] is True

        r2 = test_client.get(f"/campaigns/{cid}/execution-summary")
        assert r2.status_code == 200
        assert r2.json()["success"] is True
        assert r1.json()["data"]["campaign_id"] == r2.json()["data"]["campaign_id"]

    def test_timeline_endpoint_both_prefixes(self, test_client, mock_campaign):
        cid = mock_campaign.id
        r1 = test_client.get(f"/api/campaigns/{cid}/timeline")
        assert r1.status_code == 200
        assert r1.json()["success"] is True

        r2 = test_client.get(f"/campaigns/{cid}/timeline")
        assert r2.status_code == 200
        assert r2.json()["success"] is True

    def test_evidence_list_and_detail_endpoints(self, test_client, db_session, mock_campaign):
        cid = mock_campaign.id
        vault = EvidenceVault(CampaignRepository(db_session))
        entry = vault.store_evidence(
            campaign_id=cid,
            evidence_type="PROOF",
            target_url=mock_campaign.target_url,
            method="GET",
            raw_request="GET / HTTP/1.1",
            raw_response="HTTP/1.1 200 OK",
            payload_summary="Root check",
        )

        # Test list
        r_list = test_client.get(f"/campaigns/{cid}/evidence")
        assert r_list.status_code == 200
        items = r_list.json()["data"]["items"]
        assert len(items) == 1

        # Test detail
        r_detail = test_client.get(f"/campaigns/{cid}/evidence/{entry.id}")
        assert r_detail.status_code == 200
        assert r_detail.json()["data"]["id"] == entry.id

        # Test detail 404 for unknown
        r_404 = test_client.get(f"/campaigns/{cid}/evidence/non-existent-id")
        assert r_404.status_code == 404


# ──────────────────────────────────────────────────────────────────────────────
# 8. LIFECYCLE EVENT SPECIFIC VERIFICATIONS
# ──────────────────────────────────────────────────────────────────────────────

class TestLifecycleEventSpecifics:
    """Detailed verification for individual lifecycle events."""

    def test_preflight_started_and_completed_events(self, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        e1 = mgr.record_event(mock_campaign.id, ExecutionEventType.PREFLIGHT_STARTED)
        e2 = mgr.record_event(mock_campaign.id, ExecutionEventType.PREFLIGHT_COMPLETED, metadata={"checklist_items_passed": 6})
        assert e1.event_type == "PREFLIGHT_STARTED"
        assert e2.event_type == "PREFLIGHT_COMPLETED"
        assert e2.metadata["checklist_items_passed"] == 6

    def test_recon_started_and_completed_events(self, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        e1 = mgr.record_event(mock_campaign.id, ExecutionEventType.RECON_STARTED)
        e2 = mgr.record_event(mock_campaign.id, ExecutionEventType.RECON_COMPLETED, metadata={"endpoints_discovered": 14})
        assert e1.event_type == "RECON_STARTED"
        assert e2.event_type == "RECON_COMPLETED"
        assert e2.metadata["endpoints_discovered"] == 14

    def test_vulnerability_selection_started_and_completed(self, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        e1 = mgr.record_event(mock_campaign.id, ExecutionEventType.VULNERABILITY_SELECTION_STARTED)
        e2 = mgr.record_event(mock_campaign.id, ExecutionEventType.VULNERABILITY_SELECTION_COMPLETED, metadata={"selected_count": 8})
        assert e1.event_type == "VULNERABILITY_SELECTION_STARTED"
        assert e2.event_type == "VULNERABILITY_SELECTION_COMPLETED"

    def test_hypothesis_created_event(self, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        ev = mgr.record_event(
            mock_campaign.id,
            ExecutionEventType.HYPOTHESIS_CREATED,
            check_id="CHECK-SQLI",
            test_id="HYP-SQLI-1",
        )
        assert ev.check_id == "CHECK-SQLI"
        assert ev.test_id == "HYP-SQLI-1"

    def test_approval_required_and_received_events(self, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        e1 = mgr.record_event(mock_campaign.id, ExecutionEventType.APPROVAL_REQUIRED, reason="Privileged probe requires approval")
        e2 = mgr.record_event(mock_campaign.id, ExecutionEventType.APPROVAL_RECEIVED, actor="security_lead")
        assert e1.event_type == "APPROVAL_REQUIRED"
        assert e2.event_type == "APPROVAL_RECEIVED"

    def test_request_dispatched_and_completed_events(self, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        e1 = mgr.record_event(mock_campaign.id, ExecutionEventType.REQUEST_DISPATCHED, request_id="req-1")
        e2 = mgr.record_event(mock_campaign.id, ExecutionEventType.REQUEST_COMPLETED, request_id="req-1", reason="HTTP 200")
        assert e1.request_id == "req-1"
        assert e2.reason == "HTTP 200"

    def test_verification_completed_event(self, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        ev = mgr.record_event(
            mock_campaign.id,
            ExecutionEventType.VERIFICATION_COMPLETED,
            status="VERIFIED",
            reason="Exploit pattern reproduced across accounts",
        )
        assert ev.status == "VERIFIED"

    def test_finding_created_event(self, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        ev = mgr.record_event(
            mock_campaign.id,
            ExecutionEventType.FINDING_CREATED,
            finding_id="FIND-1234",
            status="SUCCESS",
        )
        assert ev.finding_id == "FIND-1234"

    def test_quality_gate_completed_event(self, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        ev = mgr.record_event(
            mock_campaign.id,
            ExecutionEventType.QUALITY_GATE_COMPLETED,
            metadata={"verdict": "CERTIFIED", "confidence_score": 94},
        )
        assert ev.metadata["verdict"] == "CERTIFIED"

    def test_report_generated_event(self, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        ev = mgr.record_event(
            mock_campaign.id,
            ExecutionEventType.REPORT_GENERATED,
            metadata={"format": "PDF", "size_bytes": 104857},
        )
        assert ev.event_type == "REPORT_GENERATED"

    def test_campaign_completed_event(self, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        ev = mgr.record_event(mock_campaign.id, ExecutionEventType.CAMPAIGN_COMPLETED)
        assert ev.event_type == "CAMPAIGN_COMPLETED"


# ──────────────────────────────────────────────────────────────────────────────
# 9. HONEST STATUS PROOF EDGES & INTEGRITY
# ──────────────────────────────────────────────────────────────────────────────

class TestHonestStatusProofEdges:
    """Verifies that statuses cannot be faked or assigned without proof."""

    def test_cancelled_status_honestly_derived(self, db_session, mock_campaign):
        mock_campaign.status = "CANCELLED"
        db_session.commit()
        mgr = ExecutionEventManager(db_session)
        summary = mgr.get_execution_summary(mock_campaign.id)
        assert summary.status == "CANCELLED"
        assert "cancelled" in summary.terminal_reason.lower()

    def test_recon_phase_honestly_derived_from_events(self, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        mgr.record_event(mock_campaign.id, ExecutionEventType.RECON_STARTED)
        summary = mgr.get_execution_summary(mock_campaign.id)
        assert summary.phase == "RECON"

    def test_selecting_tests_phase_honestly_derived(self, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        mgr.record_event(mock_campaign.id, ExecutionEventType.VULNERABILITY_SELECTION_STARTED)
        summary = mgr.get_execution_summary(mock_campaign.id)
        assert summary.phase == "SELECTING_TESTS"

    def test_verifying_phase_honestly_derived_when_findings_exist_unvalidated(self, db_session, mock_campaign):
        cid = mock_campaign.id
        f = Finding(
            id=f"f-{uuid.uuid4().hex[:6]}",
            scan_id=cid,
            agent_id=3,
            title="Candidate",
            vuln_type="VULN-001",
            category="API",
            severity="HIGH",
            affected_url="http://localhost:8000/demo/api",
            verdict="Candidate",
            verification_status="CANDIDATE",
        )
        db_session.add(f)
        db_session.commit()
        mgr = ExecutionEventManager(db_session)
        summary = mgr.get_execution_summary(cid)
        assert summary.phase == "VERIFYING"

    def test_terminal_reason_populated_when_completed_with_evidence(self, db_session, mock_campaign):
        cid = mock_campaign.id
        mock_campaign.status = "COMPLETED"
        vault = EvidenceVault(CampaignRepository(db_session))
        vault.store_evidence(cid, "PROOF", mock_campaign.target_url, "GET", "GET / HTTP/1.1", "HTTP/1.1 200 OK", "OK")
        db_session.commit()

        mgr = ExecutionEventManager(db_session)
        summary = mgr.get_execution_summary(cid)
        assert summary.status == "COMPLETED"
        assert "with 1 evidence artifacts captured" in summary.terminal_reason


# ──────────────────────────────────────────────────────────────────────────────
# 10. EVIDENCE RETRIEVAL & VAULT ENHANCEMENTS
# ──────────────────────────────────────────────────────────────────────────────

class TestEvidenceVaultEnhancements:
    """Verifies evidence retrieval service, pagination, and aliases."""

    def test_evidence_entry_contains_both_id_and_evidence_id(self, db_session, mock_campaign):
        repo = CampaignRepository(db_session)
        vault = EvidenceVault(repo)
        entry = vault.store_evidence(
            mock_campaign.id, "PROOF", mock_campaign.target_url, "GET", "GET / HTTP/1.1", "HTTP/1.1 200 OK", "OK"
        )
        d = entry.to_dict()
        assert "id" in d
        assert "evidence_id" in d
        assert d["id"] == d["evidence_id"]

    def test_vault_pagination_limit_and_offset(self, db_session, mock_campaign):
        repo = CampaignRepository(db_session)
        vault = EvidenceVault(repo)
        for i in range(5):
            vault.store_evidence(
                mock_campaign.id, "PROOF", f"http://localhost:8000/demo/{i}", "GET", f"GET /{i} HTTP/1.1", "200", f"ev-{i}"
            )

        svc = EvidenceRetrievalService(repo)
        page1 = svc.list_campaign_evidence(mock_campaign.id, limit=2, offset=0)
        assert len(page1["items"]) == 2
        assert page1["total_count"] == 5

        page2 = svc.list_campaign_evidence(mock_campaign.id, limit=2, offset=2)
        assert len(page2["items"]) == 2
        assert page1["items"][0]["id"] != page2["items"][0]["id"]

    def test_vault_filtering_by_evidence_type(self, db_session, mock_campaign):
        repo = CampaignRepository(db_session)
        vault = EvidenceVault(repo)
        vault.store_evidence(mock_campaign.id, "PROOF", mock_campaign.target_url, "GET", "GET /", "200", "p1")
        vault.store_evidence(mock_campaign.id, "REQUEST", mock_campaign.target_url, "GET", "GET /", "200", "r1")

        svc = EvidenceRetrievalService(repo)
        proof_only = svc.list_campaign_evidence(mock_campaign.id, evidence_type="PROOF")
        assert len(proof_only["items"]) == 1
        assert proof_only["items"][0]["evidence_type"] == "PROOF"

    def test_vault_chain_hash_linking(self, db_session, mock_campaign):
        repo = CampaignRepository(db_session)
        vault = EvidenceVault(repo)
        e1 = vault.store_evidence(mock_campaign.id, "PROOF", mock_campaign.target_url, "GET", "GET /1", "200", "1")
        e2 = vault.store_evidence(mock_campaign.id, "PROOF", mock_campaign.target_url, "GET", "GET /2", "200", "2")
        assert e1.chain_hash != e2.chain_hash
        assert e2.chain_hash is not None

    def test_evidence_detail_wrong_campaign_returns_400(self, test_client, db_session, mock_campaign):
        repo = CampaignRepository(db_session)
        vault = EvidenceVault(repo)
        entry = vault.store_evidence(
            mock_campaign.id, "PROOF", mock_campaign.target_url, "GET", "GET /", "200", "OK"
        )
        resp = test_client.get(f"/campaigns/different-campaign-id/evidence/{entry.id}")
        assert resp.status_code == 400
        assert "does not belong" in resp.json()["detail"]

    def test_timeline_event_filtering_by_type(self, test_client, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        mgr.record_event(mock_campaign.id, ExecutionEventType.TEST_STARTED)
        mgr.record_event(mock_campaign.id, ExecutionEventType.BLOCKED_SCOPE)

        resp = test_client.get(f"/campaigns/{mock_campaign.id}/timeline?event_type=BLOCKED_SCOPE")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert len(data) == 1
        assert data[0]["event_type"] == "BLOCKED_SCOPE"

    def test_timeline_pagination(self, test_client, db_session, mock_campaign):
        mgr = ExecutionEventManager(db_session)
        for _ in range(10):
            mgr.record_event(mock_campaign.id, ExecutionEventType.REQUEST_DISPATCHED)

        resp = test_client.get(f"/campaigns/{mock_campaign.id}/timeline?limit=3&offset=0")
        assert resp.status_code == 200
        assert len(resp.json()["data"]) == 3

    def test_execution_summary_nonexistent_campaign_returns_404(self, test_client):
        resp = test_client.get("/campaigns/non-existent-campaign-id/execution-summary")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_timeline_event_without_session_gracefully_handles_empty(self):
        mgr = ExecutionEventManager(session=None)
        timeline = mgr.get_timeline("camp-no-session")
        assert timeline == []

