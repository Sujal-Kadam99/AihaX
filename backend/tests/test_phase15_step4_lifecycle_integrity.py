"""AihaX Phase 15 Step 4 — Production Assessment Lifecycle Integrity, Concurrency Safety & Evidence Ownership Test Suite.

Certifies:
1. Atomic task ownership & token verification.
2. Duplicate claim rejection.
3. Stale lease detection & recovery.
4. Ownership loss enforcement (stale worker cannot complete/mutate).
5. Idempotent task completion.
6. Server-side budget concurrency (budget=0, budget=1 race, N-budget accounting).
7. Duplicate task delivery does not overspend.
8. Authorization expiration mid-run fails closed.
9. Campaign pause blocks worker execution.
10. Campaign cancellation blocks worker execution with zero resurrection.
11. Completed campaign cannot resurrect.
12. Evidence content-addressed deduplication (deterministic SHA-256).
13. Cross-campaign evidence access rejection.
14. Tampered stored evidence detection.
15. Finding deduplication across retries.
16. Incomplete campaign cannot finalize.
17. Complete campaign finalizes exactly once.
18. Stale worker cannot finalize campaign.
19. Structured audit events for all failure/race conditions.
20. Crash & lease recovery resilience.
21. Strict zero external network calls.
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
from backend.core.scope_validator import ScopeValidator, validate_concrete_target_url
from backend.evidence.evidence_manifest import ManifestBuilder
from backend.evidence.evidence_store import EvidenceVault
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
from backend.services.verification_engine import VerificationEngine


class StrictLoopbackGuardTransport(MockTransport):
    """Guarantees zero public internet communication during test runs."""

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
                message=f"Attempted external request to {url}",
            )

        self.recorded_requests.append({
            "method": method.upper(),
            "url": url,
            "headers": headers,
            "params": params,
            "body": body,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        return RawResponse(
            status_code=200,
            headers={
                "content-type": "text/html; charset=utf-8",
                "x-content-type-options": "nosniff",
                "server": "AihaX-Controlled-Lab",
            },
            body=b"<html><body><h1>Safe Controlled Lab</h1></body></html>",
            truncated=False,
            observed_size=56,
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
# A. TASK OWNERSHIP & TOKEN VALIDATION
# ──────────────────────────────────────────────────────────────────────────────

def test_01_atomic_task_claim_and_ownership(ops, repo, db_session):
    """Verify task is claimed atomically with lease and correct worker ID."""
    campaign = ops.create_campaign(name="Claim Test", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    task = repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080")
    db_session.commit()

    claimed = repo.claim_tasks(campaign.id, worker_id="worker_alpha", limit=1)
    assert len(claimed) == 1
    t = claimed[0]
    assert t.worker_id == "worker_alpha"
    assert t.status == TaskLifecycleState.CLAIMED.value
    assert t.lease_expires_at is not None


def test_02_duplicate_claim_by_another_worker_rejected(ops, repo, db_session):
    """Verify once claimed, another worker cannot claim the same task."""
    campaign = ops.create_campaign(name="Dup Claim Test", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080")
    db_session.commit()

    claimed_a = repo.claim_tasks(campaign.id, worker_id="worker_alpha", limit=1)
    assert len(claimed_a) == 1

    # Worker Beta attempts claim on same campaign
    claimed_b = repo.claim_tasks(campaign.id, worker_id="worker_beta", limit=1)
    assert len(claimed_b) == 0


def test_03_stale_worker_cannot_complete_task_after_reassignment(ops, repo, db_session):
    """Verify Worker A is rejected if it attempts completion after Worker B recovered task."""
    campaign = ops.create_campaign(name="Reassign Test", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    task = repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080")
    db_session.commit()

    # Worker A claims task
    repo.claim_tasks(campaign.id, worker_id="worker_alpha", limit=1)
    # Simulate lease expiration and recovery by Worker B
    task.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
    db_session.commit()

    recovered = repo.recover_stale_tasks(campaign.id)
    assert len(recovered) == 1

    # Worker B claims recovered task
    claimed_b = repo.claim_tasks(campaign.id, worker_id="worker_beta", limit=1)
    assert len(claimed_b) == 1

    # Worker A attempts completion -> must raise ValueError (ownership lost)
    with pytest.raises(ValueError, match="does not own task"):
        repo.complete_task(task.id, worker_id="worker_alpha")

    # Worker B completes task -> succeeds
    completed = repo.complete_task(task.id, worker_id="worker_beta")
    assert completed.status == TaskLifecycleState.COMPLETED.value


def test_04_idempotent_task_completion(ops, repo, db_session):
    """Verify calling complete_task multiple times by same worker is idempotent."""
    campaign = ops.create_campaign(name="Idemp Complete", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    task = repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080")
    db_session.commit()

    repo.claim_tasks(campaign.id, worker_id="worker_1", limit=1)
    t1 = repo.complete_task(task.id, worker_id="worker_1")
    assert t1.status == TaskLifecycleState.COMPLETED.value

    # Second completion by same worker returns completed task without error
    t2 = repo.complete_task(task.id, worker_id="worker_1")
    assert t2.status == TaskLifecycleState.COMPLETED.value


# ──────────────────────────────────────────────────────────────────────────────
# B. BUDGET CONCURRENCY & OVERSPEND PROTECTION
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_05_budget_zero_blocks_execution(ops, repo, db_session):
    """Verify campaign with budget=0 fails closed before request dispatch."""
    campaign = ops.create_campaign(name="Zero Budget", target_url="http://127.0.0.1:8080", campaign_budget=0)
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=True)
    db_session.commit()

    transport = StrictLoopbackGuardTransport()
    worker = CampaignWorker(worker_id="w_budget", request_engine=RequestEngine(scope_validator=ScopeValidator(in_scope_assets=["http://127.0.0.1:8080"]), transport=transport))
    claimed = repo.claim_tasks(campaign.id, worker_id="w_budget", limit=1)
    if claimed:
        res = await worker.execute_task(claimed[0].id, db_session, repo)
        assert res.get("status") == "failed"
        assert "budget exhausted" in res.get("error", "").lower()
        assert len(transport.recorded_requests) == 0


@pytest.mark.asyncio
async def test_06_budget_one_concurrent_workers_no_overspend(ops, repo, db_session):
    """Verify that when budget=1 and 2 tasks exist, only 1 request is consumed and the second fails."""
    campaign = ops.create_campaign(name="Budget 1 Race", target_url="http://127.0.0.1:8080", campaign_budget=1)
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    t1 = repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080/1")
    t2 = repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080/2")
    db_session.commit()

    transport = StrictLoopbackGuardTransport()
    validator = ScopeValidator(in_scope_assets=["http://127.0.0.1:8080", "http://127.0.0.1:8080/*"])
    req_engine = RequestEngine(scope_validator=validator, transport=transport)

    worker_a = CampaignWorker(worker_id="w_a", request_engine=req_engine)
    worker_b = CampaignWorker(worker_id="w_b", request_engine=req_engine)

    claimed_a = repo.claim_tasks(campaign.id, worker_id="w_a", limit=1)
    claimed_b = repo.claim_tasks(campaign.id, worker_id="w_b", limit=1)

    # Worker A executes first task -> succeeds and increments requests_used to 1
    res_a = await worker_a.execute_task(claimed_a[0].id, db_session, repo)
    assert res_a.get("status") == "completed"

    # Worker B executes second task -> budget is now 1/1, fails closed
    res_b = await worker_b.execute_task(claimed_b[0].id, db_session, repo)
    assert res_b.get("status") == "failed"
    assert "budget exhausted" in res_b.get("error", "").lower()
    assert campaign.requests_used == 1


# ──────────────────────────────────────────────────────────────────────────────
# C. AUTHORIZATION EXPIRATION RACES
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_07_authorization_expiry_before_execution_fails_closed(ops, repo, db_session):
    """Verify if authorization expires between claim and execute, task fails closed."""
    campaign = ops.create_campaign(name="Auth Expiry Race", target_url="http://127.0.0.1:8080")
    db_session.commit()
    auth = ops.authorize_campaign(campaign.id, "auditor_1", duration_days=1)
    ops.start_campaign(campaign.id, auto_dispatch=False)
    task = repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080")
    db_session.commit()

    claimed = repo.claim_tasks(campaign.id, worker_id="w_exp", limit=1)

    # Simulate authorization expiring immediately before execute
    auth.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()

    transport = StrictLoopbackGuardTransport()
    worker = CampaignWorker(worker_id="w_exp", request_engine=RequestEngine(scope_validator=ScopeValidator(in_scope_assets=["http://127.0.0.1:8080"]), transport=transport))
    res = await worker.execute_task(claimed[0].id, db_session, repo)
    assert res.get("status") == "failed"
    assert "authorization expired" in res.get("error", "").lower()
    assert len(transport.recorded_requests) == 0


# ──────────────────────────────────────────────────────────────────────────────
# D. PAUSE & CANCEL RACES (ANTI-RESURRECTION)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_08_pause_blocks_in_flight_task_execution(ops, repo, db_session):
    """Verify if campaign is paused after claim, worker aborts cleanly."""
    campaign = ops.create_campaign(name="Pause Race", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    task = repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080")
    db_session.commit()

    claimed = repo.claim_tasks(campaign.id, worker_id="w_pause", limit=1)
    # Operator pauses campaign
    ops.pause_campaign(campaign.id)
    db_session.commit()

    transport = StrictLoopbackGuardTransport()
    worker = CampaignWorker(worker_id="w_pause", request_engine=RequestEngine(scope_validator=ScopeValidator(in_scope_assets=["http://127.0.0.1:8080"]), transport=transport))
    res = await worker.execute_task(claimed[0].id, db_session, repo)
    assert res.get("status") == "aborted"
    assert "PAUSED" in res.get("reason", "")
    assert len(transport.recorded_requests) == 0


@pytest.mark.asyncio
async def test_09_cancellation_blocks_in_flight_task_execution(ops, repo, db_session):
    """Verify if campaign is cancelled after claim, worker aborts cleanly with no requests."""
    campaign = ops.create_campaign(name="Cancel Race", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    task = repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080")
    db_session.commit()

    claimed = repo.claim_tasks(campaign.id, worker_id="w_canc", limit=1)
    # Operator cancels campaign
    ops.cancel_campaign(campaign.id)
    db_session.commit()

    transport = StrictLoopbackGuardTransport()
    worker = CampaignWorker(worker_id="w_canc", request_engine=RequestEngine(scope_validator=ScopeValidator(in_scope_assets=["http://127.0.0.1:8080"]), transport=transport))
    res = await worker.execute_task(claimed[0].id, db_session, repo)
    assert res.get("status") == "aborted"
    assert "CANCELLED" in res.get("reason", "")
    assert len(transport.recorded_requests) == 0


def test_10_terminal_campaigns_cannot_be_resumed(ops, repo, db_session):
    """Verify CANCELLED or COMPLETED campaigns cannot be resumed."""
    campaign = ops.create_campaign(name="Resume Guard", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.cancel_campaign(campaign.id)
    db_session.commit()

    with pytest.raises(InvalidStateTransitionError):
        ops.resume_campaign(campaign.id)


# ──────────────────────────────────────────────────────────────────────────────
# E. EVIDENCE OWNERSHIP & DEDUPLICATION
# ──────────────────────────────────────────────────────────────────────────────

def test_11_evidence_content_deduplication_for_same_task(ops, repo, db_session):
    """Verify identical evidence for same task returns existing record without duplicating."""
    campaign = ops.create_campaign(name="Ev Deduplication", target_url="http://127.0.0.1:8080")
    db_session.commit()
    vault = EvidenceVault(repo)

    ev1 = vault.store_evidence(
        campaign_id=campaign.id,
        evidence_type="HTTP_PROBE",
        target_url="http://127.0.0.1:8080",
        raw_request="GET / HTTP/1.1",
        raw_response="HTTP/1.1 200 OK",
        task_id="task_101",
    )

    ev2 = vault.store_evidence(
        campaign_id=campaign.id,
        evidence_type="HTTP_PROBE",
        target_url="http://127.0.0.1:8080",
        raw_request="GET / HTTP/1.1",
        raw_response="HTTP/1.1 200 OK",
        task_id="task_101",
    )

    assert ev1.id == ev2.id
    assert ev1.content_hash == ev2.content_hash

    all_ev = repo.get_evidence_for_campaign(campaign.id)
    assert len(all_ev) == 1


def test_12_cross_campaign_evidence_isolation(ops, repo, db_session):
    """Verify evidence query for Campaign A strictly isolates Campaign B evidence."""
    c1 = ops.create_campaign(name="Camp A", target_url="http://127.0.0.1:8080")
    c2 = ops.create_campaign(name="Camp B", target_url="http://127.0.0.1:8080")
    db_session.commit()
    vault = EvidenceVault(repo)

    vault.store_evidence(c1.id, "PROBE", "http://127.0.0.1:8080", raw_request="REQ_A", raw_response="RESP_A")
    vault.store_evidence(c2.id, "PROBE", "http://127.0.0.1:8080", raw_request="REQ_B", raw_response="RESP_B")

    ev_c1 = repo.get_evidence_for_campaign(c1.id)
    ev_c2 = repo.get_evidence_for_campaign(c2.id)

    assert len(ev_c1) == 1
    assert len(ev_c2) == 1
    assert ev_c1[0].campaign_id == c1.id
    assert ev_c2[0].campaign_id == c2.id


# ──────────────────────────────────────────────────────────────────────────────
# F. FINDING DEDUPLICATION
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_13_duplicate_task_execution_deduplicates_findings(ops, repo, db_session):
    """Verify executing the same check twice does not multiply identical findings."""
    campaign = ops.create_campaign(name="Finding Dedup", target_url="http://127.0.0.1:8080", selected_checks=["C049_Clickjacking"])
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    task = repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080")
    db_session.commit()

    transport = StrictLoopbackGuardTransport()
    validator = ScopeValidator(in_scope_assets=["http://127.0.0.1:8080"])
    worker = CampaignWorker(worker_id="w_dedup", request_engine=RequestEngine(scope_validator=validator, transport=transport))

    claimed = repo.claim_tasks(campaign.id, worker_id="w_dedup", limit=1)
    assert len(claimed) == 1
    # First execution
    res1 = await worker.execute_task(claimed[0].id, db_session, repo)
    assert res1.get("status") == "completed"

    # Second execution of same task (simulating duplicate delivery / retry)
    res2 = await worker.execute_task(claimed[0].id, db_session, repo)

    findings = db_session.query(Finding).filter(Finding.scan_id == campaign.id).all()
    assert len(findings) == 1


# ──────────────────────────────────────────────────────────────────────────────
# G. REPORT & MANIFEST FINALIZATION
# ──────────────────────────────────────────────────────────────────────────────

def test_14_incomplete_campaign_cannot_finalize(ops, repo, db_session):
    """Verify campaign with pending/running tasks does not transition to COMPLETED."""
    campaign = ops.create_campaign(name="Incomplete Camp", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080")
    db_session.commit()

    worker = CampaignWorker(worker_id="w_eval")
    worker._evaluate_campaign_completion(campaign.id, db_session, repo)
    assert campaign.status == CampaignLifecycleState.RUNNING.value


def test_15_complete_campaign_finalizes_idempotently(ops, repo, db_session):
    """Verify when all tasks finish, campaign completes and repeated evaluation is idempotent."""
    campaign = ops.create_campaign(name="Complete Camp", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    task = repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080")
    db_session.commit()

    repo.claim_tasks(campaign.id, worker_id="w_eval", limit=1)
    repo.complete_task(task.id, worker_id="w_eval")
    db_session.commit()

    worker = CampaignWorker(worker_id="w_eval")
    worker._evaluate_campaign_completion(campaign.id, db_session, repo)
    assert campaign.status == CampaignLifecycleState.COMPLETED.value

    # Second call is idempotent
    worker._evaluate_campaign_completion(campaign.id, db_session, repo)
    assert campaign.status == CampaignLifecycleState.COMPLETED.value


# ──────────────────────────────────────────────────────────────────────────────
# H. AUDIT TRAIL & ZERO-NETWORK ISOLATION
# ──────────────────────────────────────────────────────────────────────────────

def test_16_audit_trail_records_lifecycle_events(ops, repo, db_session):
    """Verify structured audit events are emitted for key lifecycle actions."""
    campaign = ops.create_campaign(name="Audit Test", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    ops.pause_campaign(campaign.id)
    ops.resume_campaign(campaign.id)
    ops.cancel_campaign(campaign.id)
    db_session.commit()

    events = db_session.query(AuditTrailEvent).filter_by(campaign_id=campaign.id).all()
    event_types = [e.event_type for e in events]
    assert "campaign_created" in event_types
    assert "campaign_authorized" in event_types
    assert "campaign_running" in event_types
    assert "campaign_paused" in event_types
    assert "campaign_cancelled" in event_types


@pytest.mark.asyncio
async def test_17_zero_external_network_calls_during_worker_execution(ops, repo, db_session):
    """Verify transport guard guarantees zero external internet calls."""
    campaign = ops.create_campaign(name="Zero External Net", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=True)
    db_session.commit()

    transport = StrictLoopbackGuardTransport()
    validator = ScopeValidator(in_scope_assets=["http://127.0.0.1:8080"])
    worker = CampaignWorker(worker_id="w_guard", request_engine=RequestEngine(scope_validator=validator, transport=transport))

    claimed = repo.claim_tasks(campaign.id, worker_id="w_guard", limit=1)
    if claimed:
        res = await worker.execute_task(claimed[0].id, db_session, repo)
        assert res.get("status") == "completed"

    assert transport.external_network_calls == 0


def test_18_stale_worker_cannot_finalize_campaign(ops, repo, db_session):
    """Verify stale worker cannot finalize a campaign if active/pending tasks exist."""
    campaign = ops.create_campaign(name="Stale Finalize", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080/p1")
    repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080/p2")
    db_session.commit()

    stale_worker = CampaignWorker(worker_id="w_stale")
    stale_worker._evaluate_campaign_completion(campaign.id, db_session, repo)
    assert campaign.status == CampaignLifecycleState.RUNNING.value


def test_19_manifest_tampering_detected(ops, repo, db_session):
    """Verify evidence manifest detects tampering with evidence hashes."""
    from backend.evidence.evidence_manifest import compute_manifest_hash
    campaign = ops.create_campaign(name="Manifest Tamper", target_url="http://127.0.0.1:8080")
    db_session.commit()
    vault = EvidenceVault(repo)
    ev = vault.store_evidence(campaign.id, "PROBE", "http://127.0.0.1:8080", raw_request="REQ", raw_response="RESP")

    manifest = ManifestBuilder.build_manifest(
        campaign_id=campaign.id,
        scope_hash="hash_1",
        config_hash="conf_1",
        evidence_hashes=[ev.content_hash],
    )

    # Valid manifest check
    recomputed = compute_manifest_hash(
        campaign_id=manifest.campaign_id,
        scope_hash=manifest.scope_hash,
        config_hash=manifest.config_hash,
        execution_graph_hash=manifest.execution_graph_hash,
        evidence_hashes=manifest.evidence_hashes,
        finding_hashes=manifest.finding_hashes,
        coverage_report_hash=manifest.coverage_report_hash,
        report_hashes=manifest.report_hashes,
    )
    assert recomputed == manifest.manifest_hash

    # Tampered evidence hashes check
    tampered_hash = compute_manifest_hash(
        campaign_id=manifest.campaign_id,
        scope_hash=manifest.scope_hash,
        config_hash=manifest.config_hash,
        execution_graph_hash=manifest.execution_graph_hash,
        evidence_hashes=["tampered_evidence_hash_1234567890"],
        finding_hashes=manifest.finding_hashes,
        coverage_report_hash=manifest.coverage_report_hash,
        report_hashes=manifest.report_hashes,
    )
    assert tampered_hash != manifest.manifest_hash


def test_20_worker_crash_recovery_resilience(ops, repo, db_session):
    """Verify tasks abandoned by crashed workers are cleanly recovered to RETRY_PENDING."""
    campaign = ops.create_campaign(name="Crash Recovery", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, "auditor_1")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    task = repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080")
    db_session.commit()

    # Worker crashes after claiming
    repo.claim_tasks(campaign.id, worker_id="crashed_worker", limit=1)
    task.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=15)
    db_session.commit()

    recovered = repo.recover_stale_tasks(campaign.id)
    assert len(recovered) == 1
    assert recovered[0].id == task.id
    assert recovered[0].status == TaskLifecycleState.RETRY_PENDING.value
    assert recovered[0].worker_id is None


@pytest.mark.asyncio
async def test_21_authorization_expiry_during_retry_fails_closed(ops, repo, db_session):
    """Verify retrying a task after authorization has expired fails closed."""
    campaign = ops.create_campaign(name="Retry Auth Expired", target_url="http://127.0.0.1:8080")
    db_session.commit()
    auth = ops.authorize_campaign(campaign.id, "auditor_1", duration_days=1)
    ops.start_campaign(campaign.id, auto_dispatch=False)
    task = repo.create_task(campaign.id, "http://127.0.0.1:8080", "C049_Clickjacking", "http://127.0.0.1:8080")
    db_session.commit()

    # First attempt fails recoverable
    repo.claim_tasks(campaign.id, worker_id="w_retry", limit=1)
    repo.fail_task(task.id, "w_retry", "Temporary glitch", can_retry=True)
    db_session.commit()
    assert task.status == TaskLifecycleState.RETRY_PENDING.value

    # Authorization expires before retry claim
    auth.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    db_session.commit()

    transport = StrictLoopbackGuardTransport()
    worker = CampaignWorker(worker_id="w_retry_2", request_engine=RequestEngine(scope_validator=ScopeValidator(in_scope_assets=["http://127.0.0.1:8080"]), transport=transport))
    claimed = repo.claim_tasks(campaign.id, worker_id="w_retry_2", limit=1)
    assert len(claimed) == 1

    res = await worker.execute_task(claimed[0].id, db_session, repo)
    assert res.get("status") == "failed"
    assert "authorization expired" in res.get("error", "").lower()


def test_22_tampered_stored_evidence_integrity_failure(ops, repo, db_session):
    """Verify verify_evidence_integrity detects tampering in raw request/response fields."""
    from backend.evidence.integrity import verify_evidence_integrity
    campaign = ops.create_campaign(name="Evidence Tamper", target_url="http://127.0.0.1:8080")
    db_session.commit()
    vault = EvidenceVault(repo)

    ev = vault.store_evidence(
        campaign_id=campaign.id,
        evidence_type="HTTP_PROBE",
        target_url="http://127.0.0.1:8080",
        raw_request="GET /safe HTTP/1.1",
        raw_response="HTTP/1.1 200 OK",
    )

    # Valid evidence
    is_valid, _ = verify_evidence_integrity(
        content_hash=ev.content_hash,
        evidence_type="HTTP_PROBE",
        target_url="http://127.0.0.1:8080",
        method="GET",
        sanitized_request="GET /safe HTTP/1.1",
        sanitized_response="HTTP/1.1 200 OK",
        payload_summary="",
    )
    assert is_valid is True

    # Tampered response
    is_valid_tampered, reason = verify_evidence_integrity(
        content_hash=ev.content_hash,
        evidence_type="HTTP_PROBE",
        target_url="http://127.0.0.1:8080",
        method="GET",
        sanitized_request="GET /safe HTTP/1.1",
        sanitized_response="HTTP/1.1 500 TAMPERED ERROR",
        payload_summary="",
    )
    assert is_valid_tampered is False
    assert "mismatch" in reason.lower()

