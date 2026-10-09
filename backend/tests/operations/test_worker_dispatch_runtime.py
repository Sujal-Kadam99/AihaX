"""AihaX Phase 13.y — Worker Dispatch, Runtime Execution, and Anti-Stall Tests.

Comprehensive suite covering:
1. Start creates initial task
2. Start does not duplicate tasks (idempotency)
3. Worker starts and runs dispatch cycle
4. Worker claims pending task
5. Claim sets worker_id
6. Claim sets lease_expires_at
7. Heartbeat updates activity and lease
8. Worker executes claimed task
9. Phase progresses during real work
10. Mock evidence is generated and persisted
11. Cancelled campaign cannot be claimed
12. Cancelled task cannot resurrect
13. Stale task recovery works
14. Stalled campaign is detected when no worker is active
15. Running campaign with active heartbeat is not falsely stalled
16. Worker startup failure is observable
17. Zero-network runtime execution works (100% mocked)
18. Multiple campaigns remain isolated
"""

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.core.check_registry import registry
from backend.models.database import Base, Finding, Program, ProgramScope
from backend.persistence.models import Campaign, ExecutionTask
from backend.persistence.repository import CampaignRepository
from backend.persistence.state_machine import (
    CampaignLifecycleState,
    InvalidStateTransitionError,
    TaskLifecycleState,
)
from backend.services.campaign_operations import CampaignOperationsService
from backend.services.campaign_worker import CampaignWorker, CampaignWorkerRuntime
from backend.services.request_engine import (
    MockTransport,
    RawResponse,
    RequestEngine,
    RequestSpec,
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
    """Isolated in-memory SQLite database session."""
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def mock_request_engine():
    """Zero-network deterministic request engine."""
    transport = MockTransport(
        default_status=200,
        default_headers={
            "Content-Type": "text/html",
            "Server": "nginx/1.24",
            "Strict-Transport-Security": "max-age=31536000",
        },
        default_body=b"<html><head><title>AihaX Mock Target</title></head><body><h1>Safe Target</h1></body></html>",
    )
    from backend.core.scope_validator import ScopeValidator
    return RequestEngine(
        scope_validator=ScopeValidator(in_scope_assets=["*"]),
        transport=transport,
        rate_limit_rps=50,
        max_concurrency=5,
    )


def _setup_authorized_campaign(session, target_url="https://example.test.local"):
    """Helper to create a fully authorized program and campaign."""
    repo = CampaignRepository(session)
    ops = CampaignOperationsService(repo)

    prog = Program(id=f"prog-{uuid.uuid4().hex[:6]}", name="Authorized Test Program")
    scope = ProgramScope(
        program_id=prog.id,
        in_scope_assets=json.dumps(["*.test.local", target_url]),
        out_of_scope_assets=json.dumps(["https://evil.com"]),
    )
    session.add(prog)
    session.add(scope)
    session.flush()

    camp = ops.create_campaign(
        name="Worker Test Campaign",
        target_url=target_url,
        program_id=prog.id,
    )
    ops.authorize_campaign(camp.id, authorized_by="security_officer")
    session.commit()
    return camp, prog


# ──────────────────────────────────────────────────────────────────────────────
# TEST CASES 1 TO 18
# ──────────────────────────────────────────────────────────────────────────────

def test_1_start_creates_initial_task(db_session):
    """1. Starting an authorized campaign creates real execution task(s)."""
    camp, _ = _setup_authorized_campaign(db_session)
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)

    updated = ops.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    assert updated.status == CampaignLifecycleState.RUNNING.value
    tasks = db_session.query(ExecutionTask).filter(ExecutionTask.campaign_id == camp.id).all()
    assert len(tasks) >= 1
    assert tasks[0].status == TaskLifecycleState.PENDING.value
    assert tasks[0].target_url == "https://example.test.local"
    assert "*" not in tasks[0].target_url


def test_2_start_does_not_duplicate_task(db_session):
    """2. Re-starting an already RUNNING campaign does not create duplicate tasks."""
    camp, _ = _setup_authorized_campaign(db_session)
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)

    ops.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()
    initial_count = db_session.query(ExecutionTask).filter(ExecutionTask.campaign_id == camp.id).count()

    # Second start
    ops.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()
    second_count = db_session.query(ExecutionTask).filter(ExecutionTask.campaign_id == camp.id).count()

    assert initial_count == second_count


@pytest.mark.parametrize(
    ("mode", "expected_task"),
    [
        ("RECON_ONLY", "PIPELINE_RECON_ONLY"),
        ("SAFE_SCAN", "PIPELINE_RECON_THEN_VTA"),
    ],
)
def test_campaign_mode_queues_the_correct_ordered_pipeline(db_session, mode, expected_task):
    camp, _ = _setup_authorized_campaign(db_session)
    camp.mode = mode
    db_session.flush()

    CampaignOperationsService(CampaignRepository(db_session)).start_campaign(camp.id, auto_dispatch=True)

    tasks = db_session.query(ExecutionTask).filter(ExecutionTask.campaign_id == camp.id).all()
    assert len(tasks) == 1
    assert tasks[0].check_id == expected_task


def test_campaign_tool_selection_defaults_to_zap_and_allows_explicit_disable(db_session):
    ops = CampaignOperationsService(CampaignRepository(db_session))
    default_campaign = ops.create_campaign(name="Default Tools", target_url="https://example.test.local")
    disabled_campaign = ops.create_campaign(
        name="No Optional Tools", target_url="https://other.test.local", selected_tools=[]
    )

    default_snapshot = json.loads(CampaignRepository(db_session).get_snapshot(default_campaign.id).snapshot_json)
    disabled_snapshot = json.loads(CampaignRepository(db_session).get_snapshot(disabled_campaign.id).snapshot_json)
    assert default_snapshot["selected_tools"] == ["zap"]
    assert disabled_snapshot["selected_tools"] == []


@pytest.mark.asyncio
async def test_3_worker_starts(db_session):
    """3. CampaignWorkerRuntime starts and stops cleanly."""
    runtime = CampaignWorkerRuntime(poll_interval=0.1)
    assert not runtime.is_running
    await runtime.start()
    assert runtime.is_running
    await runtime.stop()
    assert not runtime.is_running


def test_4_worker_claims_pending_task(db_session):
    """4. Worker claims a pending task, transitioning it to CLAIMED."""
    camp, _ = _setup_authorized_campaign(db_session)
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    ops.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    worker = CampaignWorker(worker_id="test-worker-01")
    claimed = repo.claim_tasks(camp.id, worker.worker_id, limit=5)
    db_session.commit()

    assert len(claimed) >= 1
    for t in claimed:
        assert t.status == TaskLifecycleState.CLAIMED.value


def test_5_claim_sets_worker_id(db_session):
    """5. Claiming a task persists worker_id."""
    camp, _ = _setup_authorized_campaign(db_session)
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    ops.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    worker = CampaignWorker(worker_id="agent-smith-99")
    claimed = repo.claim_tasks(camp.id, worker.worker_id, limit=1)
    db_session.commit()

    assert len(claimed) == 1
    assert claimed[0].worker_id == "agent-smith-99"


def test_6_claim_sets_lease(db_session):
    """6. Claiming a task persists lease_expires_at in the future."""
    camp, _ = _setup_authorized_campaign(db_session)
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    ops.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    now = datetime.now(timezone.utc)
    worker = CampaignWorker(worker_id="worker-lease-test", lease_duration_seconds=45)
    claimed = repo.claim_tasks(camp.id, worker.worker_id, limit=1, lease_duration_seconds=45)
    db_session.commit()

    assert len(claimed) == 1
    assert claimed[0].lease_expires_at is not None
    # Lease must expire ~45s in future
    delta = (claimed[0].lease_expires_at - now).total_seconds()
    assert 40 <= delta <= 50


def test_7_heartbeat_updates_activity(db_session):
    """7. Renewing task lease updates lease_expires_at and keeps runtime activity fresh."""
    camp, _ = _setup_authorized_campaign(db_session)
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    ops.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    worker = CampaignWorker(worker_id="worker-hb-01")
    claimed = repo.claim_tasks(camp.id, worker.worker_id, limit=1)
    db_session.commit()
    t = claimed[0]

    old_lease = t.lease_expires_at
    # Renew lease
    renewed = repo.renew_task_lease(t.id, worker.worker_id, lease_duration_seconds=60)
    db_session.commit()

    assert renewed is True
    db_session.refresh(t)
    assert t.lease_expires_at > old_lease


@pytest.mark.asyncio
async def test_8_worker_executes_claimed_task(db_session, mock_request_engine):
    """8. Worker successfully executes a claimed task and marks it COMPLETED."""
    camp, _ = _setup_authorized_campaign(db_session)
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    ops.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    worker = CampaignWorker(worker_id="worker-exec-01", request_engine=mock_request_engine)
    claimed = repo.claim_tasks(camp.id, worker.worker_id, limit=1)
    db_session.commit()
    assert len(claimed) == 1

    task_id = claimed[0].id
    res = await worker.execute_task(task_id, db_session, repo)

    assert res["status"] == "completed"
    db_session.refresh(claimed[0])
    assert claimed[0].status == TaskLifecycleState.COMPLETED.value
    assert claimed[0].completed_at is not None


@pytest.mark.asyncio
async def test_9_phase_progresses(db_session, mock_request_engine):
    """9. Campaign phase progresses from TESTING to COMPLETED as tasks finish."""
    camp, _ = _setup_authorized_campaign(db_session)
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    ops.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    worker = CampaignWorker(worker_id="worker-phase-01", request_engine=mock_request_engine)

    # Initial state: RUNNING
    truth_initial = ops.get_campaign_runtime_truth(camp.id)
    assert truth_initial["status"] == "RUNNING"
    assert truth_initial["is_stalled"] is False

    # Claim and execute all tasks
    tasks = db_session.query(ExecutionTask).filter(ExecutionTask.campaign_id == camp.id).all()
    for t in tasks:
        repo.claim_tasks(camp.id, worker.worker_id, limit=1)
        db_session.commit()
        await worker.execute_task(t.id, db_session, repo)

    db_session.refresh(camp)
    assert camp.status == CampaignLifecycleState.COMPLETED.value
    truth_final = ops.get_campaign_runtime_truth(camp.id)
    assert truth_final["current_phase"] == "COMPLETED"
    assert truth_final["active_operation"] == "Assessment campaign completed."


@pytest.mark.asyncio
async def test_10_mock_evidence_generated(db_session, mock_request_engine):
    """10. Zero-network execution persists cryptographic evidence in database."""
    camp, _ = _setup_authorized_campaign(db_session)
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    ops.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    worker = CampaignWorker(worker_id="worker-ev-01", request_engine=mock_request_engine)
    claimed = repo.claim_tasks(camp.id, worker.worker_id, limit=1)
    db_session.commit()

    await worker.execute_task(claimed[0].id, db_session, repo)

    ev_records = repo.get_evidence_for_campaign(camp.id)
    assert len(ev_records) >= 1
    assert ev_records[0].content_hash is not None
    assert len(ev_records[0].content_hash) == 64  # Valid SHA-256


def test_11_cancelled_campaign_cannot_be_claimed(db_session):
    """11. Cancelled campaigns return 0 claimed tasks."""
    camp, _ = _setup_authorized_campaign(db_session)
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    ops.start_campaign(camp.id, auto_dispatch=True)
    ops.cancel_campaign(camp.id)
    db_session.commit()

    worker = CampaignWorker(worker_id="worker-cancel-test")
    claimed = repo.claim_tasks(camp.id, worker.worker_id, limit=5)

    assert claimed == []


def test_12_cancelled_task_cannot_resurrect(db_session):
    """12. Stale task recovery never resurrects tasks from cancelled campaigns."""
    camp, _ = _setup_authorized_campaign(db_session)
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    ops.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    # Worker claims task
    claimed = repo.claim_tasks(camp.id, "dead_worker", limit=1)
    db_session.commit()
    t = claimed[0]

    # Campaign cancelled
    ops.cancel_campaign(camp.id)
    db_session.commit()

    # Expire lease
    t.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=100)
    db_session.commit()

    # Recovery coordinator
    recovered = repo.recover_stale_tasks(camp.id)
    assert recovered == []

    db_session.refresh(t)
    assert t.status == TaskLifecycleState.CANCELLED.value


def test_13_stale_task_recovery_works(db_session):
    """13. Stale tasks on active campaigns are recovered to RETRY_PENDING."""
    camp, _ = _setup_authorized_campaign(db_session)
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    ops.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    claimed = repo.claim_tasks(camp.id, "crashed_worker", limit=1, lease_duration_seconds=5)
    db_session.commit()
    t = claimed[0]

    # Expire lease
    t.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
    db_session.commit()

    recovered = repo.recover_stale_tasks(camp.id)
    assert len(recovered) == 1
    assert recovered[0].id == t.id
    assert recovered[0].status == TaskLifecycleState.RETRY_PENDING.value
    assert recovered[0].worker_id is None


def test_14_stalled_campaign_is_detected(db_session):
    """14. A RUNNING campaign with 0 active workers and expired activity is detected as stalled."""
    camp, _ = _setup_authorized_campaign(db_session)
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    ops.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    # Simulate campaign created & started 500 seconds ago with 0 worker activity
    old_time = datetime.now(timezone.utc) - timedelta(seconds=500)
    camp.created_at = old_time
    camp.started_at = old_time
    tasks = db_session.query(ExecutionTask).filter(ExecutionTask.campaign_id == camp.id).all()
    for t in tasks:
        t.created_at = old_time
        t.started_at = None
        t.lease_expires_at = None
    from backend.persistence.models import AuditTrailEvent
    events = db_session.query(AuditTrailEvent).filter(AuditTrailEvent.campaign_id == camp.id).all()
    for e in events:
        e.timestamp = old_time
    db_session.commit()

    truth = ops.get_campaign_runtime_truth(camp.id, stale_threshold_seconds=120)
    assert truth["is_stalled"] is True
    assert truth["current_phase"] == "RUNNING — NO RECENT PROGRESS"
    assert "No worker heartbeat" in truth["stalled_reason"]


def test_15_running_campaign_with_active_heartbeat_is_not_falsely_stalled(db_session):
    """15. A RUNNING campaign with an active leased task is not flagged as stalled."""
    camp, _ = _setup_authorized_campaign(db_session)
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    ops.start_campaign(camp.id, auto_dispatch=True)
    db_session.commit()

    worker = CampaignWorker(worker_id="active-worker-live", lease_duration_seconds=60)
    repo.claim_tasks(camp.id, worker.worker_id, limit=1)
    db_session.commit()

    truth = ops.get_campaign_runtime_truth(camp.id, stale_threshold_seconds=120)
    assert truth["is_stalled"] is False
    assert truth["current_phase"] in ("RECON", "TESTING", "VERIFICATION")
    assert "active worker" in truth["active_operation"].lower()


@pytest.mark.asyncio
async def test_16_worker_startup_failure_is_observable(db_session):
    """16. Worker failure on invalid task is logged and recorded cleanly."""
    camp, _ = _setup_authorized_campaign(db_session)
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    ops.start_campaign(camp.id, auto_dispatch=False)
    db_session.commit()

    # Create task with invalid target
    t = repo.create_task(camp.id, "https://invalid.target", "C002_Missing_Security_Headers", "https://invalid.target")
    claimed = repo.claim_tasks(camp.id, "worker-err-01", limit=1)
    db_session.commit()

    # Custom engine that raises an error
    class ErrorTransport(MockTransport):
        async def send(self, spec: RequestSpec):
            raise ConnectionRefusedError("Simulated connection refused")

    from backend.core.scope_validator import ScopeValidator
    err_engine = RequestEngine(
        scope_validator=ScopeValidator(in_scope_assets=["*"]),
        transport=ErrorTransport(),
        rate_limit_rps=10,
        max_concurrency=1,
    )
    worker = CampaignWorker(worker_id="worker-err-01", request_engine=err_engine)

    res = await worker.execute_task(t.id, db_session, repo)
    assert res["status"] == "failed"

    db_session.refresh(t)
    assert t.status in (TaskLifecycleState.RETRY_PENDING.value, TaskLifecycleState.FAILED.value)
    assert t.failure_reason is not None


@pytest.mark.asyncio
async def test_17_zero_network_runtime_execution_works(session_factory, mock_request_engine):
    """17. End-to-end campaign dispatch and execution completes with 0 external network requests."""
    session = session_factory()
    camp, _ = _setup_authorized_campaign(session)
    repo = CampaignRepository(session)
    ops = CampaignOperationsService(repo)
    ops.start_campaign(camp.id, auto_dispatch=True)
    session.commit()
    session.close()

    runtime = CampaignWorkerRuntime(
        custom_request_engine=mock_request_engine,
        worker_concurrency=5,
        session_factory=session_factory,
    )

    # Perform dispatch passes until all tasks complete
    total_executed = 0
    while True:
        executed = await runtime.dispatch_once()
        if executed == 0:
            break
        total_executed += executed

    assert total_executed >= 1

    check_session = session_factory()
    camp_updated = check_session.query(Campaign).filter(Campaign.id == camp.id).first()
    assert camp_updated.status == CampaignLifecycleState.COMPLETED.value
    assert camp_updated.requests_used >= 1
    assert camp_updated.manifest_hash is not None
    check_session.close()


@pytest.mark.asyncio
async def test_18_multiple_campaigns_remain_isolated(session_factory, mock_request_engine):
    """18. Multiple concurrent campaigns maintain separate task queues and isolated states."""
    session = session_factory()
    camp1, _ = _setup_authorized_campaign(session, target_url="https://alpha.test.local")
    camp2, _ = _setup_authorized_campaign(session, target_url="https://beta.test.local")

    repo = CampaignRepository(session)
    ops = CampaignOperationsService(repo)

    ops.start_campaign(camp1.id, auto_dispatch=True)
    ops.start_campaign(camp2.id, auto_dispatch=True)
    session.commit()

    # Cancel campaign 1
    ops.cancel_campaign(camp1.id)
    session.commit()
    session.close()

    runtime = CampaignWorkerRuntime(
        custom_request_engine=mock_request_engine,
        worker_concurrency=20,
        session_factory=session_factory,
    )
    while True:
        executed = await runtime.dispatch_once()
        if executed == 0:
            break

    check_session = session_factory()
    c1 = check_session.query(Campaign).filter(Campaign.id == camp1.id).first()
    c2 = check_session.query(Campaign).filter(Campaign.id == camp2.id).first()

    # Campaign 1 remains CANCELLED, Campaign 2 completes cleanly
    assert c1.status == CampaignLifecycleState.CANCELLED.value
    assert c2.status == CampaignLifecycleState.COMPLETED.value
    check_session.close()
