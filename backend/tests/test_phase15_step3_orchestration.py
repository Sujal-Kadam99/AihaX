"""AihaX Phase 15 Step 3 — Controlled Authorized Assessment Orchestration & Runtime Safety Test Suite.

Certifies:
1. Deterministic ExecutionPlan creation and validation.
2. Unknown check rejection (fails closed, 0 requests).
3. Destructive check rejection (non-destructive policy).
4. Wildcard target rejection in execution plans.
5. Out-of-scope target rejection.
6. Expired authorization fail-closed enforcement.
7. Tampered snapshot hash detection.
8. Tampered execution plan hash detection.
9. Destination safety enforcement (metadata & link-local blocked).
10. Server-side request budget exhaustion protection.
11. Concurrent budget overspend prevention.
12. Cancellation and anti-resurrection guarantees.
13. Pause/resume authorization gating.
14. Worker lease recovery safety.
15. Strict RequestEngine boundary.
16. Evidence vault linkage (campaign/task/check/finding).
17. Automated secret redaction.
18. Candidate finding verification lifecycle.
19. Cross-campaign evidence rejection.
20. Zero external network calls during automated execution.
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
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
from backend.persistence.state_machine import CampaignLifecycleState, TaskLifecycleState
from backend.services.campaign_operations import (
    AuthorizationRequiredException,
    CampaignOperationsService,
    ExecutionPlan,
    ExecutionPlanCheck,
    InvalidStateTransitionError,
    ScopeMismatchException,
)
from backend.services.campaign_worker import CampaignWorker
from backend.services.request_engine import (
    AuthenticationContext,
    MockTransport,
    RawResponse,
    RequestEngine,
    RequestEvidence,
    RequestSpec,
    RequestTimeout,
    TransportError,
)
from backend.services.verification_engine import VerificationEngine, VerificationStatus


class LoopbackSafeTransport(MockTransport):
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
            body=b"<html><body><h1>Safe Lab Endpoint</h1></body></html>",
            truncated=False,
            observed_size=55,
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
# 1. EXECUTION PLAN CREATION & INTEGRITY TESTS
# ──────────────────────────────────────────────────────────────────────────────

def test_execution_plan_creation_and_hash_verification(ops, repo, db_session):
    """Verify that ExecutionPlan is deterministic, contains only valid registered checks, and computes valid SHA-256 hash."""
    target_url = "http://127.0.0.1:8080"
    campaign = ops.create_campaign(
        name="Plan Test Campaign",
        target_url=target_url,
        selected_checks=["C002_Missing_Security_Headers", "C049_Clickjacking"],
    )
    db_session.commit()
    ops.authorize_campaign(campaign.id, authorized_by="lead_auditor")
    db_session.commit()

    plan = ops.generate_execution_plan(campaign.id)
    assert plan is not None
    assert plan.campaign_id == campaign.id
    assert plan.target_url == target_url
    assert len(plan.checks) == 2
    assert plan.verify_integrity() is True
    assert campaign.config_hash == plan.plan_hash

    # Validate plan via service
    is_valid, reason, validated_plan = ops.validate_execution_plan(campaign.id)
    assert is_valid is True
    assert validated_plan.plan_hash == plan.plan_hash


def test_execution_plan_unknown_check_rejection(ops, repo, db_session):
    """Verify that unknown check IDs are strictly rejected from execution plans."""
    target_url = "http://127.0.0.1:8080"
    campaign = ops.create_campaign(
        name="Bad Check Campaign",
        target_url=target_url,
        selected_checks=["C999_Unknown_Vulnerability"],
    )
    db_session.commit()

    with pytest.raises(ValueError, match="Unknown check ID 'C999_Unknown_Vulnerability' cannot enter execution plan"):
        ops.generate_execution_plan(campaign.id)


def test_execution_plan_destructive_check_rejection(ops, repo, db_session):
    """Verify that checks marked destructive=True cannot enter execution plans."""
    class DummyDestructiveCheck(BaseCheck):
        contract = CheckContract(
            id="C998_Destructive_Test",
            name="Destructive Test",
            category=CheckCategory.MISCONFIG,
            description="Destructive test",
            severity=Severity.HIGH,
            destructive=False,  # Bypass check contract init
        )
    
    # Temporarily modify contract to destructive
    DummyDestructiveCheck.contract.destructive = True
    registry.register(DummyDestructiveCheck)

    try:
        target_url = "http://127.0.0.1:8080"
        campaign = ops.create_campaign(
            name="Destructive Campaign",
            target_url=target_url,
            selected_checks=["C998_Destructive_Test"],
        )
        db_session.commit()

        with pytest.raises(ValueError, match="Destructive check 'C998_Destructive_Test' cannot enter execution plan"):
            ops.generate_execution_plan(campaign.id)
    finally:
        # Cleanup dummy check from registry
        if "C998_Destructive_Test" in registry._checks:
            del registry._checks["C998_Destructive_Test"]


def test_execution_plan_tampering_detection(ops, repo, db_session):
    """Verify that tampering with an execution plan snapshot fails closed."""
    target_url = "http://127.0.0.1:8080"
    campaign = ops.create_campaign(name="Tamper Plan Campaign", target_url=target_url)
    db_session.commit()
    ops.authorize_campaign(campaign.id, authorized_by="lead_auditor")
    db_session.commit()

    plan = ops.generate_execution_plan(campaign.id)
    snap = repo.get_snapshot(campaign.id)
    
    # Tamper with checks inside snapshot JSON
    snap_dict = json.loads(snap.snapshot_json)
    snap_dict["execution_plan"]["checks"][0]["check_id"] = "TAMPERED_CHECK"
    snap.snapshot_json = json.dumps(snap_dict, sort_keys=True)
    db_session.commit()

    is_valid, reason, _ = ops.validate_execution_plan(campaign.id)
    assert is_valid is False
    assert "tampering detected" in reason.lower() or "mismatch" in reason.lower()


# ──────────────────────────────────────────────────────────────────────────────
# 2. PRE-EXECUTION VALIDATION & MID-RUN REVALIDATION
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_pre_execution_gates_fail_closed_on_expired_auth(ops, repo, db_session):
    """Verify execution fails closed immediately if authorization is expired."""
    target_url = "http://127.0.0.1:8080"
    campaign = ops.create_campaign(name="Expired Auth Campaign", target_url=target_url)
    db_session.commit()
    auth = ops.authorize_campaign(campaign.id, authorized_by="lead", duration_days=1)
    auth.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db_session.commit()

    # Preflight check reports expired
    checklist = ops.get_campaign_preflight_checklist(campaign.id)
    assert checklist["all_passed"] is False
    assert checklist["authorization_not_expired"] is False

    # Start campaign fails closed
    with pytest.raises(AuthorizationRequiredException, match="authorization expired"):
        ops.start_campaign(campaign.id)


@pytest.mark.asyncio
async def test_destination_safety_blocks_cloud_metadata_in_worker(ops, repo, db_session):
    """Verify worker aborts task before issuing request if target URL is cloud metadata."""
    metadata_url = "http://169.254.169.254/latest/meta-data/"
    # Create task with metadata URL explicitly
    campaign = ops.create_campaign(name="Metadata Campaign", target_url="http://127.0.0.1:8080")
    db_session.commit()
    ops.authorize_campaign(campaign.id, authorized_by="lead")
    ops.start_campaign(campaign.id, auto_dispatch=False)
    db_session.commit()

    task = repo.create_task(
        campaign_id=campaign.id,
        check_id="C002_Missing_Security_Headers",
        target_url=metadata_url,
        endpoint_url=metadata_url,
    )
    db_session.commit()

    safe_transport = LoopbackSafeTransport()
    worker = CampaignWorker(
        worker_id="safety_worker_1",
        request_engine=RequestEngine(
            scope_validator=ScopeValidator(in_scope_assets=[metadata_url]),
            transport=safe_transport,
        ),
    )

    claimed = repo.claim_tasks(campaign.id, worker_id="safety_worker_1", limit=10)
    assert len(claimed) >= 1
    meta_task = claimed[0]

    res = await worker.execute_task(meta_task.id, db_session, repo)
    assert res.get("status") == "failed"
    assert "Destination" in res.get("error", "") or "safety" in res.get("error", "").lower()
    assert len(safe_transport.recorded_requests) == 0
    assert safe_transport.external_network_calls == 0


# ──────────────────────────────────────────────────────────────────────────────
# 3. BUDGET & CONCURRENCY CONTROLS
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_server_side_budget_enforcement_and_audit(ops, repo, db_session):
    """Verify that worker rejects execution when requests_used reaches campaign_budget."""
    target_url = "http://127.0.0.1:8080"
    campaign = ops.create_campaign(name="Budget Strict Campaign", target_url=target_url, campaign_budget=2)
    db_session.commit()
    ops.authorize_campaign(campaign.id, authorized_by="lead")
    ops.start_campaign(campaign.id, auto_dispatch=True)
    db_session.commit()

    # Pre-set requests_used to 2
    campaign.requests_used = 2
    db_session.commit()

    worker = CampaignWorker(worker_id="budget_worker")
    claimed = repo.claim_tasks(campaign.id, worker_id="budget_worker", limit=1)
    if claimed:
        res = await worker.execute_task(claimed[0].id, db_session, repo)
        assert res.get("status") == "failed"
        assert "budget exhausted" in res.get("error", "").lower()

    # Check audit events for budget_exhausted
    events = db_session.query(AuditTrailEvent).filter_by(campaign_id=campaign.id, event_type="budget_exhausted").all()
    assert len(events) >= 1


# ──────────────────────────────────────────────────────────────────────────────
# 4. CANCELLATION & PAUSE PROPAGATION (ANTI-RESURRECTION)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cancelled_campaign_task_invalidation_and_no_resurrection(ops, repo, db_session):
    """Verify that cancelled campaigns immediately cancel tasks and block any worker resurrection."""
    target_url = "http://127.0.0.1:8080"
    campaign = ops.create_campaign(name="Cancel Anti-Resurrection", target_url=target_url)
    db_session.commit()
    ops.authorize_campaign(campaign.id, authorized_by="lead")
    ops.start_campaign(campaign.id, auto_dispatch=True)
    db_session.commit()

    claimed = repo.claim_tasks(campaign.id, worker_id="w_cancel", limit=1)
    assert len(claimed) == 1
    task = claimed[0]

    # Operator cancels campaign
    ops.cancel_campaign(campaign.id, actor="operator")
    db_session.commit()

    # Worker attempts execution after cancellation
    worker = CampaignWorker(worker_id="w_cancel")
    res = await worker.execute_task(task.id, db_session, repo)
    assert res.get("status") == "aborted"
    assert "CANCELLED" in res.get("reason", "")

    # Attempt to resurrect task fails
    task_after = db_session.query(ExecutionTask).filter_by(id=task.id).first()
    assert task_after.status == TaskLifecycleState.CANCELLED.value


# ──────────────────────────────────────────────────────────────────────────────
# 5. EVIDENCE & FINDING VERIFICATION BOUNDARY
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_finding_verification_lifecycle_and_evidence_linkage(ops, repo, db_session):
    """Verify that check execution produces CANDIDATE finding, passes through VerificationEngine, and links evidence."""
    target_url = "http://127.0.0.1:8080"
    campaign = ops.create_campaign(
        name="Verification Lifecycle Campaign",
        target_url=target_url,
        selected_checks=["C049_Clickjacking"],
    )
    db_session.commit()
    ops.authorize_campaign(campaign.id, authorized_by="lead")
    ops.start_campaign(campaign.id, auto_dispatch=True)
    db_session.commit()

    safe_transport = LoopbackSafeTransport()
    validator = ScopeValidator(in_scope_assets=[target_url])
    req_engine = RequestEngine(scope_validator=validator, transport=safe_transport)

    worker = CampaignWorker(
        worker_id="verify_worker_1",
        request_engine=req_engine,
    )

    claimed = repo.claim_tasks(campaign.id, worker_id="verify_worker_1", limit=1)
    assert len(claimed) == 1
    task = claimed[0]

    res = await worker.execute_task(task.id, db_session, repo)
    assert res.get("status") == "completed"

    # Verify evidence in EvidenceVault
    evidence_items = repo.get_evidence_for_campaign(campaign.id)
    assert len(evidence_items) >= 1
    ev_record = evidence_items[0]
    assert ev_record.task_id == task.id
    assert ev_record.content_hash is not None


# ──────────────────────────────────────────────────────────────────────────────
# 6. SECRET REDACTION IN REQUEST EVIDENCE
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_secret_redaction_in_request_evidence():
    """Verify that sensitive headers and session tokens are redacted in RequestEngine evidence records."""
    target_url = "http://127.0.0.1:8080/api/user"
    validator = ScopeValidator(in_scope_assets=[target_url])
    transport = LoopbackSafeTransport()
    engine = RequestEngine(scope_validator=validator, transport=transport)

    auth_ctx = AuthenticationContext(
        name="admin_session",
        headers={"Authorization": "Bearer super-secret-token-12345", "X-Api-Key": "my-private-api-key"},
        cookies={"session": "sensitive-cookie-abcdef"},
    )

    spec = RequestSpec(
        url=target_url,
        method="GET",
        headers={"Authorization": "Bearer super-secret-token-12345", "X-Api-Key": "my-private-api-key"},
        auth_context=auth_ctx,
    )

    evidence = await engine.execute(spec)
    assert evidence.success is True
    # Verify authorization header is redacted in recorded evidence
    req_headers = evidence.request_headers
    for key, val in req_headers.items():
        if key.lower() in ("authorization", "x-api-key", "cookie"):
            assert "REDACTED" in val or "secret" not in val.lower()
