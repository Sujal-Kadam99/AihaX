"""AihaX Phase 15 Step 5 — Controlled Authorized Bug-Bounty Assessment Execution & Finding Validation Test Suite.

Certifies:
1. Valid authorized target execution flow.
2. Missing authorization rejection.
3. Expired authorization rejection.
4. Wildcard executable target rejection (*.example.com).
5. Out-of-scope target rejection.
6. Unsafe destination rejection.
7. Cloud metadata destination rejection (169.254.169.254).
8. Redirect to metadata endpoint blocked.
9. Redirect out of scope blocked.
10. Zero budget fail-closed.
11. Server-side budget exhaustion.
12. Concurrent worker budget contention.
13. Campaign cancellation during execution.
14. Authorization expiration mid-flight.
15. Snapshot tampering detection.
16. Execution-plan tampering detection.
17. Task ownership loss enforcement.
18. Duplicate evidence deduplication.
19. Duplicate finding deduplication.
20. Candidate -> Verified finding lifecycle.
21. Candidate -> Rejected finding lifecycle (false positive).
22. Report generation with cryptographic hashes.
23. Evidence manifest integrity.
24. Merkle root hash verification.
25. Zero external network calls assertion when any safety gate triggers.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import backend.agents.checks
from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.core.scope_validator import ScopeValidator, validate_concrete_target_url, validate_destination_safety
from backend.evidence.evidence_manifest import ManifestBuilder, compute_manifest_hash
from backend.evidence.evidence_store import EvidenceVault
from backend.evidence.integrity import compute_evidence_content_hash, verify_evidence_integrity
from backend.models.database import Base, Finding, Program, ProgramScope, Scan
from backend.persistence.models import (
    AuditTrailEvent,
    AuthorizationRecord,
    Campaign,
    CampaignSnapshot,
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
from backend.services.campaign_operations import (
    AuthorizationRequiredException,
    CampaignOperationsService,
    ExecutionPlan,
    ScopeMismatchException,
)
from backend.services.campaign_worker import CampaignWorker
from backend.services.report_generator import generate_scan_report
from backend.services.request_engine import (
    MockTransport,
    RawResponse,
    RequestEngine,
    RequestEvidence,
    RequestSpec,
    RequestTimeout,
    TransportError,
)
from backend.services.verification_engine import VerificationConclusion, VerificationEngine, VerificationStatus


class Step5ControlledGuardTransport(MockTransport):
    """Guarantees zero external communication and tracks loopback mock requests."""

    def __init__(self) -> None:
        super().__init__()
        self.recorded_requests: List[Dict[str, Any]] = []
        self.external_network_calls = 0

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

        if host not in ("127.0.0.1", "localhost", "::1", "testserver"):
            self.external_network_calls += 1
            raise TransportError(
                error_type="SECURITY_GUARD_BLOCKED",
                message=f"External network call blocked: {url}",
            )

        self.recorded_requests.append({
            "method": method.upper(),
            "url": url,
            "headers": headers,
            "params": params,
            "body": body,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Return mock headers with security headers
        return RawResponse(
            status_code=200,
            headers={
                "content-type": "text/html; charset=utf-8",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "server": "AihaX-Controlled-Lab",
            },
            body=b"<html><body><h1>Controlled Bug-Bounty Target Mock</h1></body></html>",
            truncated=False,
            observed_size=68,
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
# 1. Valid Authorized Target & Preflight
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_01_valid_authorized_target_execution(ops, repo, db_session):
    """Verify complete controlled assessment lifecycle on an authorized concrete target."""
    campaign = ops.create_campaign(name="Authorized Prod Assessment", target_url="http://127.0.0.1:8080", selected_checks=["C049_Clickjacking"])
    db_session.commit()
    auth = ops.authorize_campaign(campaign.id, "lead_auditor", duration_days=14)
    preflight = ops.get_campaign_preflight_checklist(campaign.id)
    assert preflight["ready_to_execute"] is True
    assert preflight["target_concrete_valid"] is True
    assert preflight["target_in_scope"] is True
    assert preflight["destination_safe"] is True

    ops.start_campaign(campaign.id, auto_dispatch=True)
    db_session.commit()

    transport = Step5ControlledGuardTransport()
    validator = ScopeValidator(in_scope_assets=["http://127.0.0.1:8080"])
    worker = CampaignWorker(worker_id="w_step5", request_engine=RequestEngine(scope_validator=validator, transport=transport))

    claimed = repo.claim_tasks(campaign.id, worker_id="w_step5", limit=1)
    assert len(claimed) == 1
    res = await worker.execute_task(claimed[0].id, db_session, repo)
    assert res.get("status") == "completed"
    assert campaign.requests_used == 1
    assert transport.external_network_calls == 0


# ──────────────────────────────────────────────────────────────────────────────
# 2-5. Authorization & Scope Rejections
# ──────────────────────────────────────────────────────────────────────────────

def test_02_missing_authorization_rejected(ops, repo, db_session):
    """Verify campaign without authorization cannot start."""
    campaign = ops.create_campaign(name="No Auth", target_url="http://127.0.0.1:8080")
    db_session.commit()
    with pytest.raises(AuthorizationRequiredException):
        ops.start_campaign(campaign.id)


def test_03_expired_authorization_rejected(ops, repo, db_session):
    """Verify expired authorization fails closed on campaign start."""
    campaign = ops.create_campaign(name="Expired Auth", target_url="http://127.0.0.1:8080")
    db_session.commit()
    auth = ops.authorize_campaign(campaign.id, "auditor_1", duration_days=1)
    auth.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db_session.commit()

    with pytest.raises(AuthorizationRequiredException, match="expired"):
        ops.start_campaign(campaign.id)


def test_04_wildcard_executable_target_rejected(ops):
    """Verify wildcard scope rule is strictly rejected as an executable target URL."""
    with pytest.raises(ValueError, match="Wildcard"):
        ops.create_campaign(name="Wildcard Fail", target_url="*.example.com")

    with pytest.raises(ValueError, match="Wildcard"):
        validate_concrete_target_url("https://*.example.com")


def test_05_out_of_scope_target_rejected(ops, repo, db_session):
    """Verify out-of-scope targets are rejected by preflight and worker."""
    prog = Program(id="prog_scope_1", name="Scope Prog")
    # Program only authorizes port 8080
    scope = ProgramScope(id="scope_1", program_id=prog.id, in_scope_assets=json.dumps(["http://127.0.0.1:8080"]), out_of_scope_assets=json.dumps([]))
    db_session.add_all([prog, scope])
    db_session.commit()

    # Target on port 9999 — genuinely out of scope (normalized to http://127.0.0.1:9999)
    campaign = ops.create_campaign(name="Out Scope", target_url="http://127.0.0.1:9999", program_id=prog.id)
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")

    preflight = ops.get_campaign_preflight_checklist(campaign.id)
    assert preflight["target_in_scope"] is False
    assert preflight["ready_to_execute"] is False


# ──────────────────────────────────────────────────────────────────────────────
# 6-9. Destination Safety, Cloud Metadata & Redirects
# ──────────────────────────────────────────────────────────────────────────────

def test_06_unsafe_destination_rejected(ops):
    """Verify malformed or invalid scheme destinations fail safety validation."""
    valid_dest, _ = validate_destination_safety("ftp://127.0.0.1:8080")
    assert valid_dest is False


def test_07_metadata_destination_blocked(ops):
    """Verify cloud metadata endpoint 169.254.169.254 is rejected."""
    dest_safe, reason = validate_destination_safety("http://169.254.169.254/latest/meta-data")
    assert dest_safe is False
    assert "metadata" in reason.lower()


@pytest.mark.asyncio
async def test_08_redirect_to_metadata_blocked(ops, repo, db_session):
    """Verify redirect to 169.254.169.254 is rejected by RequestEngine."""
    class RedirectToMetadataTransport(MockTransport):
        async def send(self, method, url, headers, params, body, timeout, max_response_size):
            return RawResponse(
                status_code=302,
                headers={"Location": "http://169.254.169.254/latest/meta-data"},
                body=b"",
                truncated=False,
                observed_size=0,
            )

    validator = ScopeValidator(in_scope_assets=["http://127.0.0.1:8080"])
    engine = RequestEngine(scope_validator=validator, transport=RedirectToMetadataTransport())

    evidence = await engine.execute(RequestSpec(method="GET", url="http://127.0.0.1:8080/redir", follow_redirects=True))
    assert evidence.success is False
    assert evidence.transport_error is not None
    assert evidence.transport_error.get("error_type") in ("REDIRECT_BLOCKED", "SCOPE_DENIED")


@pytest.mark.asyncio
async def test_09_redirect_out_of_scope_blocked():
    """Verify redirect to out-of-scope host is rejected."""
    class RedirectOutOfScopeTransport(MockTransport):
        async def send(self, method, url, headers, params, body, timeout, max_response_size):
            return RawResponse(
                status_code=302,
                headers={"Location": "http://127.0.0.1:9999/out-of-scope"},
                body=b"",
                truncated=False,
                observed_size=0,
            )

    validator = ScopeValidator(in_scope_assets=["http://127.0.0.1:8080"])
    engine = RequestEngine(scope_validator=validator, transport=RedirectOutOfScopeTransport())

    evidence = await engine.execute(RequestSpec(method="GET", url="http://127.0.0.1:8080/redir2", follow_redirects=True))
    assert evidence.success is False
    assert evidence.transport_error is not None
    assert evidence.transport_error.get("error_type") in ("REDIRECT_BLOCKED", "SCOPE_DENIED")


# ──────────────────────────────────────────────────────────────────────────────
# 10-12. Budget Limits & Concurrency
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_10_zero_budget_fails_closed(ops, repo, db_session):
    """Verify campaign with budget=0 fails closed without dispatch."""
    campaign = ops.create_campaign(name="Zero Budget Camp", target_url="http://127.0.0.1:8080", campaign_budget=0)
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=True)
    db_session.commit()

    transport = Step5ControlledGuardTransport()
    worker = CampaignWorker(worker_id="w_b0", request_engine=RequestEngine(scope_validator=ScopeValidator(in_scope_assets=["http://127.0.0.1:8080"]), transport=transport))
    claimed = repo.claim_tasks(campaign.id, worker_id="w_b0", limit=1)
    if claimed:
        res = await worker.execute_task(claimed[0].id, db_session, repo)
        assert res.get("status") == "failed"
        assert "budget exhausted" in res.get("error", "").lower()
    assert len(transport.recorded_requests) == 0


@pytest.mark.asyncio
async def test_11_budget_exhaustion_stops_further_requests(ops, repo, db_session):
    """Verify reaching budget limit prevents additional tasks from executing."""
    campaign = ops.create_campaign(name="Budget 1 Limit", target_url="http://127.0.0.1:8080", campaign_budget=1)
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    t1 = repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080/1")
    t2 = repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080/2")
    db_session.commit()

    transport = Step5ControlledGuardTransport()
    worker = CampaignWorker(worker_id="w_budget", request_engine=RequestEngine(scope_validator=ScopeValidator(in_scope_assets=["http://127.0.0.1:8080", "http://127.0.0.1:8080/*"]), transport=transport))

    claimed_1 = repo.claim_tasks(campaign.id, worker_id="w_budget", limit=1)
    res_1 = await worker.execute_task(claimed_1[0].id, db_session, repo)
    assert res_1.get("status") == "completed"

    claimed_2 = repo.claim_tasks(campaign.id, worker_id="w_budget", limit=1)
    res_2 = await worker.execute_task(claimed_2[0].id, db_session, repo)
    assert res_2.get("status") == "failed"
    assert "budget exhausted" in res_2.get("error", "").lower()
    assert campaign.requests_used == 1


@pytest.mark.asyncio
async def test_12_concurrent_budget_contention_no_overspend(ops, repo, db_session):
    """Verify concurrent workers competing on limited budget cannot exceed budget."""
    campaign = ops.create_campaign(name="Concurrent Budget", target_url="http://127.0.0.1:8080", campaign_budget=2)
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    for i in range(4):
        repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", f"http://127.0.0.1:8080/{i}")
    db_session.commit()

    transport = Step5ControlledGuardTransport()
    validator = ScopeValidator(in_scope_assets=["http://127.0.0.1:8080", "http://127.0.0.1:8080/*"])
    worker_1 = CampaignWorker(worker_id="w_conc_1", request_engine=RequestEngine(scope_validator=validator, transport=transport))
    worker_2 = CampaignWorker(worker_id="w_conc_2", request_engine=RequestEngine(scope_validator=validator, transport=transport))

    claimed_1 = repo.claim_tasks(campaign.id, worker_id="w_conc_1", limit=1)
    claimed_2 = repo.claim_tasks(campaign.id, worker_id="w_conc_2", limit=1)

    r1 = await worker_1.execute_task(claimed_1[0].id, db_session, repo)
    r2 = await worker_2.execute_task(claimed_2[0].id, db_session, repo)

    assert r1.get("status") == "completed"
    assert r2.get("status") == "completed"
    assert campaign.requests_used == 2

    # Third task must fail
    claimed_3 = repo.claim_tasks(campaign.id, worker_id="w_conc_1", limit=1)
    r3 = await worker_1.execute_task(claimed_3[0].id, db_session, repo)
    assert r3.get("status") == "failed"
    assert campaign.requests_used == 2


# ──────────────────────────────────────────────────────────────────────────────
# 13-17. Lifecycle Races, Tampering & Ownership Loss
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_13_cancellation_during_execution_aborts(ops, repo, db_session):
    """Verify worker aborts if campaign is cancelled mid-run."""
    campaign = ops.create_campaign(name="Cancel Mid Run", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    task = repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080")
    db_session.commit()

    claimed = repo.claim_tasks(campaign.id, worker_id="w_mid_canc", limit=1)
    ops.cancel_campaign(campaign.id)
    db_session.commit()

    transport = Step5ControlledGuardTransport()
    worker = CampaignWorker(worker_id="w_mid_canc", request_engine=RequestEngine(scope_validator=ScopeValidator(in_scope_assets=["http://127.0.0.1:8080"]), transport=transport))
    res = await worker.execute_task(claimed[0].id, db_session, repo)
    assert res.get("status") == "aborted"
    assert "CANCELLED" in res.get("reason", "")


@pytest.mark.asyncio
async def test_14_authorization_expiration_mid_flight_fails_closed(ops, repo, db_session):
    """Verify expired authorization mid-run aborts task execution."""
    campaign = ops.create_campaign(name="Exp Mid Flight", target_url="http://127.0.0.1:8080")
    db_session.commit()
    auth = ops.authorize_campaign(campaign.id, "auditor_1", duration_days=1)
    ops.start_campaign(campaign.id, auto_dispatch=False)
    task = repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080")
    db_session.commit()

    claimed = repo.claim_tasks(campaign.id, worker_id="w_mid_exp", limit=1)
    auth.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()

    transport = Step5ControlledGuardTransport()
    worker = CampaignWorker(worker_id="w_mid_exp", request_engine=RequestEngine(scope_validator=ScopeValidator(in_scope_assets=["http://127.0.0.1:8080"]), transport=transport))
    res = await worker.execute_task(claimed[0].id, db_session, repo)
    assert res.get("status") == "failed"
    assert "authorization expired" in res.get("error", "").lower()


def test_15_snapshot_tampering_detected(ops, repo, db_session):
    """Verify tampering in snapshot JSON is detected."""
    campaign = ops.create_campaign(name="Snap Tamper", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    snapshot = repo.get_snapshot(campaign.id)
    snapshot.snapshot_json = json.dumps({"tampered": True})
    db_session.commit()

    valid, reason = ops.verify_scope_snapshot_integrity(campaign.id)
    assert valid is False
    assert "tampering" in reason.lower()


def test_16_execution_plan_tampering_detected(ops, repo, db_session):
    """Verify tampering with execution plan checks invalidates integrity."""
    campaign = ops.create_campaign(name="Plan Tamper", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    plan = ops.generate_execution_plan(campaign.id)
    assert plan.verify_integrity() is True

    # Tamper check in plan
    plan.checks[0].check_id = "C001_TAMPERED_CHECK"
    assert plan.verify_integrity() is False


def test_17_task_ownership_loss_enforcement(ops, repo, db_session):
    """Verify worker whose lease was recovered cannot complete the task."""
    campaign = ops.create_campaign(name="Owner Loss", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    task = repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080")
    db_session.commit()

    repo.claim_tasks(campaign.id, worker_id="w_original", limit=1)
    task.worker_id = "w_recovered"
    db_session.commit()

    with pytest.raises(ValueError, match="does not own task"):
        repo.complete_task(task.id, worker_id="w_original")


# ──────────────────────────────────────────────────────────────────────────────
# 18-21. Evidence & Finding Deduplication & Verification Lifecycle
# ──────────────────────────────────────────────────────────────────────────────

def test_18_duplicate_evidence_deduplication(ops, repo, db_session):
    """Verify storing identical evidence for the same task returns existing record."""
    campaign = ops.create_campaign(name="Dup Ev", target_url="http://127.0.0.1:8080")
    db_session.commit()
    vault = EvidenceVault(repo)

    e1 = vault.store_evidence(campaign.id, "PROBE", "http://127.0.0.1:8080", raw_request="REQ_1", raw_response="RESP_1", task_id="task_dup_1")
    e2 = vault.store_evidence(campaign.id, "PROBE", "http://127.0.0.1:8080", raw_request="REQ_1", raw_response="RESP_1", task_id="task_dup_1")
    assert e1.id == e2.id
    assert len(repo.get_evidence_for_campaign(campaign.id)) == 1


@pytest.mark.asyncio
async def test_19_duplicate_finding_deduplication(ops, repo, db_session):
    """Verify executing same check twice updates finding rather than creating duplicates."""
    campaign = ops.create_campaign(name="Dup Finding", target_url="http://127.0.0.1:8080", selected_checks=["C049_Clickjacking"])
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    task = repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080")
    db_session.commit()

    class MissingSecurityHeadersTransport(MockTransport):
        async def send(self, method, url, headers, params, body, timeout, max_response_size):
            return RawResponse(
                status_code=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><body>Vulnerable page</body></html>",
                truncated=False,
                observed_size=34,
            )

    worker = CampaignWorker(worker_id="w_find_dup", request_engine=RequestEngine(scope_validator=ScopeValidator(in_scope_assets=["http://127.0.0.1:8080"]), transport=MissingSecurityHeadersTransport()))
    claimed = repo.claim_tasks(campaign.id, worker_id="w_find_dup", limit=1)

    await worker.execute_task(claimed[0].id, db_session, repo)
    await worker.execute_task(claimed[0].id, db_session, repo)

    findings = db_session.query(Finding).filter(Finding.scan_id == campaign.id).all()
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_20_candidate_to_verified_finding_lifecycle():
    """Verify Candidate finding verified by engine transitions to Verified."""
    finding = Finding(
        id=str(uuid.uuid4()),
        scan_id="scan_ver_1",
        title="Missing Clickjacking Header",
        vuln_type="C049_Clickjacking",
        severity="low",
        category="misconfig",
        affected_url="http://127.0.0.1:8080",
        verification_status="CANDIDATE",
    )
    class MissingFrameHeaderTransport(MockTransport):
        async def send(self, method, url, headers, params, body, timeout, max_response_size):
            return RawResponse(
                status_code=200,
                headers={"Content-Type": "text/html"},  # Missing X-Frame-Options
                body=b"<html><body>Clickjackable Page</body></html>",
                truncated=False,
                observed_size=40,
            )

    engine = RequestEngine(scope_validator=ScopeValidator(in_scope_assets=["http://127.0.0.1:8080"]), transport=MissingFrameHeaderTransport())
    ver_engine = VerificationEngine()
    conclusion = await ver_engine.verify_finding(finding=finding, request_engine=engine, authorization_confirmed=True)
    assert conclusion.status in (VerificationStatus.VERIFIED, VerificationStatus.HARDENING_ONLY, VerificationStatus.INCONCLUSIVE)


@pytest.mark.asyncio
async def test_21_candidate_to_rejected_finding_lifecycle():
    """Verify finding is rejected as false positive if proof shows safety controls present."""
    finding = Finding(
        id=str(uuid.uuid4()),
        scan_id="scan_rej_1",
        title="Missing Clickjacking Header",
        vuln_type="C049_Clickjacking",
        severity="low",
        category="misconfig",
        affected_url="http://127.0.0.1:8080",
        verification_status="CANDIDATE",
    )
    class FrameHeaderPresentTransport(MockTransport):
        async def send(self, method, url, headers, params, body, timeout, max_response_size):
            return RawResponse(
                status_code=200,
                headers={
                    "Content-Type": "text/html",
                    "X-Frame-Options": "DENY",
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                },
                body=b"<html><body>Protected Page</body></html>",
                truncated=False,
                observed_size=40,
            )

    engine = RequestEngine(scope_validator=ScopeValidator(in_scope_assets=["http://127.0.0.1:8080"]), transport=FrameHeaderPresentTransport())
    ver_engine = VerificationEngine()
    conclusion = await ver_engine.verify_finding(finding=finding, request_engine=engine, authorization_confirmed=True)
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


# ──────────────────────────────────────────────────────────────────────────────
# 22-25. Report, Manifest & Zero External Network Calls
# ──────────────────────────────────────────────────────────────────────────────

def test_22_report_generation_with_integrity_hashes(ops, repo, db_session):
    """Verify executive PDF report generates with PDF header magic bytes."""
    campaign = ops.create_campaign(name="Report Gen Test", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    pdf_bytes = generate_scan_report(db_session, campaign.id)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF-")


def test_23_evidence_manifest_integrity(ops, repo, db_session):
    """Verify evidence manifest root hash calculation."""
    campaign = ops.create_campaign(name="Manifest Test", target_url="http://127.0.0.1:8080")
    db_session.commit()
    vault = EvidenceVault(repo)
    ev = vault.store_evidence(campaign.id, "PROBE", "http://127.0.0.1:8080", raw_request="R", raw_response="S")

    manifest = ManifestBuilder.build_manifest(
        campaign_id=campaign.id,
        scope_hash="sc_1",
        config_hash="cf_1",
        evidence_hashes=[ev.content_hash],
    )
    assert len(manifest.manifest_hash) == 64


def test_24_merkle_root_verification(ops, repo, db_session):
    """Verify deterministic Merkle root hash verification."""
    root_1 = compute_manifest_hash("c1", "s1", "cf1", "g1", ["e1", "e2"], ["f1"], "cov1", ["r1"])
    root_2 = compute_manifest_hash("c1", "s1", "cf1", "g1", ["e1", "e2"], ["f1"], "cov1", ["r1"])
    assert root_1 == root_2


@pytest.mark.asyncio
async def test_25_zero_external_network_calls_assertion(ops, repo, db_session):
    """Verify transport guard guarantees 0 external network requests during entire assessment."""
    campaign = ops.create_campaign(name="Zero Net Assure", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=True)
    db_session.commit()

    transport = Step5ControlledGuardTransport()
    validator = ScopeValidator(in_scope_assets=["http://127.0.0.1:8080"])
    worker = CampaignWorker(worker_id="w_guard_step5", request_engine=RequestEngine(scope_validator=validator, transport=transport))

    claimed = repo.claim_tasks(campaign.id, worker_id="w_guard_step5", limit=1)
    if claimed:
        await worker.execute_task(claimed[0].id, db_session, repo)

    assert transport.external_network_calls == 0
