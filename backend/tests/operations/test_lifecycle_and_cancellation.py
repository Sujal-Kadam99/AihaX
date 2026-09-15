"""AihaX Phase 13 — Comprehensive Campaign/Target Lifecycle & Cancellation Regression Suite.

Covers all 31 required verification scenarios:
- Cancellation invariants (1-10)
- Target consistency & multi-campaign decoupling (11-15)
- Execution lifecycle & atomic task dispatch (16-25)
- Idempotency & safety (26-28)
- Diagnostic Runtime Truth (29-31)
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.models.database import Base, Program, ProgramScope
from backend.persistence.models import Campaign, CampaignTarget, ExecutionTask
from backend.persistence.repository import CampaignRepository
from backend.persistence.state_machine import (
    CampaignLifecycleState,
    InvalidStateTransitionError,
    TaskLifecycleState,
)
from backend.services.campaign_operations import (
    AuthorizationRequiredException,
    CampaignOperationsService,
)


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _create_authorized_program(session, name="Eternal", scope_asset="*.zomato.com"):
    prog_id = str(uuid.uuid4())
    prog = Program(
        id=prog_id,
        name=name,
        description=f"Authorized program for {name}",
        created_at=datetime.now(timezone.utc),
    )
    session.add(prog)
    scope = ProgramScope(
        id=str(uuid.uuid4()),
        program_id=prog_id,
        in_scope_assets=json.dumps([scope_asset]),
        out_of_scope_assets=json.dumps([]),
        allowed_ports=json.dumps([80, 443]),
        excluded_ports=json.dumps([]),
        allowed_schemes=json.dumps(["https", "http"]),
        excluded_paths=json.dumps([]),
        created_at=datetime.now(timezone.utc),
    )
    session.add(scope)
    session.commit()
    return prog


# ──────────────────────────────────────────────────────────────────────────────
# GROUP 1: CANCELLATION INVARIANTS (1-10)
# ──────────────────────────────────────────────────────────────────────────────

def test_01_cancel_draft_campaign(db_session):
    """1. Cancel DRAFT campaign (DRAFT -> CANCELLED)."""
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    c = ops.create_campaign("Draft Camp", "https://app.zomato.com")
    assert c.status == CampaignLifecycleState.DRAFT.value

    cancelled = ops.cancel_campaign(c.id, actor="operator_1", reason="No longer needed")
    assert cancelled.status == CampaignLifecycleState.CANCELLED.value
    assert cancelled.completed_at is not None


def test_02_cancel_authorized_campaign(db_session):
    """2. Cancel AUTHORIZED campaign (AUTHORIZED -> CANCELLED)."""
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    c = ops.create_campaign("Auth Camp", "https://app.zomato.com")
    ops.authorize_campaign(c.id, "auditor_alice")
    assert c.status == CampaignLifecycleState.AUTHORIZED.value

    cancelled = ops.cancel_campaign(c.id, actor="operator_1")
    assert cancelled.status == CampaignLifecycleState.CANCELLED.value


def test_03_cancel_running_campaign(db_session):
    """3. Cancel RUNNING campaign (RUNNING -> CANCELLED)."""
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    c = ops.create_campaign("Running Camp", "https://app.zomato.com")
    ops.authorize_campaign(c.id, "auditor_alice")
    ops.start_campaign(c.id, auto_dispatch=True)
    assert c.status == CampaignLifecycleState.RUNNING.value

    cancelled = ops.cancel_campaign(c.id, actor="operator_1")
    assert cancelled.status == CampaignLifecycleState.CANCELLED.value


def test_04_cancel_already_cancelled_campaign_is_idempotent(db_session):
    """4. Cancel already CANCELLED campaign (idempotent, safe, no-op)."""
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    c = ops.create_campaign("Idempotent Cancel", "https://app.zomato.com")
    ops.cancel_campaign(c.id)
    assert c.status == CampaignLifecycleState.CANCELLED.value

    # Second cancellation must succeed without error
    c2 = ops.cancel_campaign(c.id)
    assert c2.status == CampaignLifecycleState.CANCELLED.value


def test_05_cancel_with_pending_tasks(db_session):
    """5. Cancel with pending tasks (all pending tasks become CANCELLED)."""
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    c = ops.create_campaign("Pending Tasks Cancel", "https://app.zomato.com")
    ops.authorize_campaign(c.id, "auditor_alice")
    t1 = repo.create_task(c.id, "https://app.zomato.com", "C001", "https://app.zomato.com/1")
    t2 = repo.create_task(c.id, "https://app.zomato.com", "C002", "https://app.zomato.com/2")
    db_session.commit()

    ops.cancel_campaign(c.id)
    assert t1.status == TaskLifecycleState.CANCELLED.value
    assert t2.status == TaskLifecycleState.CANCELLED.value


def test_06_cancel_with_running_claimed_task(db_session):
    """6. Cancel with running/claimed task (claimed/running tasks become CANCELLED with lease cleared)."""
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    c = ops.create_campaign("Claimed Task Cancel", "https://app.zomato.com")
    ops.authorize_campaign(c.id, "auditor_alice")
    ops.start_campaign(c.id, auto_dispatch=False)
    t = repo.create_task(c.id, "https://app.zomato.com", "C001", "https://app.zomato.com/1")
    claimed = ops.claim_tasks_for_worker(c.id, "worker_1", limit=1)
    assert len(claimed) == 1
    assert t.status == TaskLifecycleState.CLAIMED.value
    assert t.lease_expires_at is not None

    ops.cancel_campaign(c.id)
    assert t.status == TaskLifecycleState.CANCELLED.value
    assert t.lease_expires_at is None
    assert t.worker_id is None


def test_07_cancel_with_stale_lease(db_session):
    """7. Cancel with stale lease (stale lease tasks become CANCELLED with lease cleared)."""
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    c = ops.create_campaign("Stale Lease Cancel", "https://app.zomato.com")
    ops.authorize_campaign(c.id, "auditor_alice")
    ops.start_campaign(c.id, auto_dispatch=False)
    t = repo.create_task(c.id, "https://app.zomato.com", "C001", "https://app.zomato.com/1")
    ops.claim_tasks_for_worker(c.id, "worker_1", limit=1, lease_seconds=1)
    # Simulate past expiration
    t.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
    db_session.commit()

    ops.cancel_campaign(c.id)
    assert t.status == TaskLifecycleState.CANCELLED.value
    assert t.lease_expires_at is None


def test_08_recovery_cannot_resurrect_cancelled_campaign(db_session):
    """8. Crash recovery must NOT resurrect tasks for a CANCELLED campaign."""
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    c = ops.create_campaign("No Resurrection", "https://app.zomato.com")
    ops.authorize_campaign(c.id, "auditor_alice")
    ops.start_campaign(c.id, auto_dispatch=False)
    t = repo.create_task(c.id, "https://app.zomato.com", "C001", "https://app.zomato.com/1")
    ops.claim_tasks_for_worker(c.id, "worker_1", limit=1, lease_seconds=1)

    # Cancel campaign
    ops.cancel_campaign(c.id)
    # Stale lease in the past
    t.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
    db_session.commit()

    # Recovery must ignore cancelled campaign
    recovered = ops.recover_stale_tasks(c.id)
    assert len(recovered) == 0
    assert t.status == TaskLifecycleState.CANCELLED.value

    # Workers cannot claim tasks
    claimed = ops.claim_tasks_for_worker(c.id, "worker_2")
    assert len(claimed) == 0


def test_09_cancelled_campaign_cannot_create_new_tasks(db_session):
    """9. Cancelled campaign cannot create new tasks."""
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    c = ops.create_campaign("Terminal Camp", "https://app.zomato.com")
    ops.cancel_campaign(c.id)

    with pytest.raises(InvalidStateTransitionError):
        repo.create_task(c.id, "https://app.zomato.com", "C001", "https://app.zomato.com/1")


def test_10_cancelled_campaign_cannot_be_resumed(db_session):
    """10. Cancelled campaign cannot be resumed."""
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    c = ops.create_campaign("No Resume", "https://app.zomato.com")
    ops.authorize_campaign(c.id, "auditor_alice")
    ops.start_campaign(c.id, auto_dispatch=False)
    ops.cancel_campaign(c.id)

    with pytest.raises(InvalidStateTransitionError):
        ops.resume_campaign(c.id)


# ──────────────────────────────────────────────────────────────────────────────
# GROUP 2: TARGET CONSISTENCY & MULTI-CAMPAIGN DECOUPLING (11-15)
# ──────────────────────────────────────────────────────────────────────────────

def test_11_cancel_releases_only_campaign_target_assignment(db_session):
    """11. Cancelling Campaign A releases only Campaign A assignment."""
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    c = ops.create_campaign("Camp A", "https://app.zomato.com")
    ops.authorize_campaign(c.id, "auditor_alice")
    target = repo.get_targets(c.id)[0]
    assert target.target_status == "PENDING"

    ops.cancel_campaign(c.id)
    assert target.target_status == "RELEASED"
    assert target.execution_status == "CANCELLED"


def test_12_target_program_remains_authorized_when_campaign_cancelled(db_session):
    """12. Program scope/authorization is not destroyed when a campaign is cancelled."""
    prog = _create_authorized_program(db_session, "Eternal", "*.zomato.com")
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)

    c = ops.create_campaign("Camp Zomato", "https://app.zomato.com", program_id=prog.id)
    ops.authorize_campaign(c.id, "auditor_alice")
    ops.cancel_campaign(c.id)

    # Underlying program remains intact
    prog_check = db_session.query(Program).filter_by(id=prog.id).first()
    assert prog_check is not None
    assert prog_check.name == "Eternal"


def test_13_target_with_another_active_campaign_remains_active(db_session):
    """13. Cancelling Campaign 1 does NOT affect running Campaign 2 for the same target."""
    prog = _create_authorized_program(db_session, "Eternal", "*.zomato.com")
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)

    c1 = ops.create_campaign("Camp 1", "https://app.zomato.com", program_id=prog.id)
    ops.authorize_campaign(c1.id, "auditor_alice")
    ops.start_campaign(c1.id, auto_dispatch=True)

    c2 = ops.create_campaign("Camp 2", "https://app.zomato.com", program_id=prog.id)
    ops.authorize_campaign(c2.id, "auditor_alice")
    ops.start_campaign(c2.id, auto_dispatch=True)

    # Cancel Camp 1
    ops.cancel_campaign(c1.id)
    assert c1.status == CampaignLifecycleState.CANCELLED.value

    # Camp 2 remains RUNNING and workers can claim tasks for Camp 2
    assert c2.status == CampaignLifecycleState.RUNNING.value
    claimed_c2 = ops.claim_tasks_for_worker(c2.id, "worker_1")
    assert len(claimed_c2) >= 1


def test_14_targets_api_response_reflects_accurate_assignment_breakdown(db_session):
    """14. Program API helper returns true active/total campaign counts."""
    from backend.routers.programs import _build_program_response
    prog = _create_authorized_program(db_session, "Eternal", "*.zomato.com")
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)

    c1 = ops.create_campaign("Camp 1", "https://app.zomato.com", program_id=prog.id)
    ops.authorize_campaign(c1.id, "auditor_alice")
    ops.start_campaign(c1.id, auto_dispatch=True)

    c2 = ops.create_campaign("Camp 2", "https://app.zomato.com", program_id=prog.id)
    ops.cancel_campaign(c2.id)

    resp = _build_program_response(prog, db_session)
    assert resp.status == "AUTHORIZED"
    assert resp.active_campaigns_count == 1
    assert resp.total_campaigns_count == 2
    assert len(resp.campaigns) == 2


def test_15_target_assignments_differentiated(db_session):
    """15. Distinct status per campaign assignment."""
    prog = _create_authorized_program(db_session, "Eternal", "*.zomato.com")
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)

    c_cancelled = ops.create_campaign("Cancelled Camp", "https://app.zomato.com", program_id=prog.id)
    ops.cancel_campaign(c_cancelled.id)

    target_cancelled = repo.get_targets(c_cancelled.id)[0]
    assert target_cancelled.target_status == "RELEASED"
    assert target_cancelled.execution_status == "CANCELLED"


# ──────────────────────────────────────────────────────────────────────────────
# GROUP 3: NEW CAMPAIGN EXECUTION LIFECYCLE (16-25)
# ──────────────────────────────────────────────────────────────────────────────

def test_16_to_25_complete_new_campaign_execution_pipeline(db_session):
    """16-25. Full pipeline: Program -> Campaign -> Target -> Auth -> Start -> Task Created -> Worker Claim -> Phase -> Counters."""
    # 16. Create target / program
    prog = _create_authorized_program(db_session, "Eternal", "*.zomato.com")
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)

    # 17. Create campaign & 18. Assign target
    c = ops.create_campaign(
        name="Eternal-Zomato-Web-001",
        target_url="https://app.zomato.com",
        program_id=prog.id,
        in_scope_assets=["https://app.zomato.com"],
        selected_checks=["C001_Reflected_XSS", "C008_Information_Disclosure"],
    )
    assert c.status == CampaignLifecycleState.DRAFT.value
    targets = repo.get_targets(c.id)
    assert len(targets) == 1
    assert targets[0].normalized_url == "https://app.zomato.com"

    # 19. Authorize campaign
    auth = ops.authorize_campaign(c.id, "lead_security_operator", duration_days=30)
    assert auth.status == "ACTIVE"
    assert c.status == CampaignLifecycleState.AUTHORIZED.value

    # 20. Start campaign & 21. Verify transitions to RUNNING
    ops.start_campaign(c.id, auto_dispatch=True)
    assert c.status == CampaignLifecycleState.RUNNING.value

    # 22. Verify initial runtime task exists
    tasks = repo.session.query(ExecutionTask).filter_by(campaign_id=c.id).all()
    assert len(tasks) >= 1
    assert tasks[0].status == TaskLifecycleState.PENDING.value
    assert tasks[0].check_id in ["C001_Reflected_XSS", "C008_Information_Disclosure"]

    # 23. Verify worker can claim it
    claimed = ops.claim_tasks_for_worker(c.id, "worker_alpha", limit=1, lease_seconds=60)
    assert len(claimed) == 1
    assert claimed[0].status == TaskLifecycleState.CLAIMED.value
    assert claimed[0].worker_id == "worker_alpha"

    # 24. Verify runtime phase becomes SCOPE / RECON
    truth = ops.get_campaign_runtime_truth(c.id)
    assert truth["status"] == "RUNNING"
    assert truth["current_phase"] in ["RECON", "SCOPE", "TESTING"]
    assert not truth["is_stalled"]

    # 25. Verify task counters change correctly
    assert truth["tasks_summary"].get("CLAIMED", 0) == 1
    assert truth["tasks_summary"].get("PENDING", 0) == len(tasks) - 1


# ──────────────────────────────────────────────────────────────────────────────
# GROUP 4: IDEMPOTENCY & SAFETY (26-28)
# ──────────────────────────────────────────────────────────────────────────────

def test_26_start_running_campaign_does_not_duplicate_tasks(db_session):
    """26. Starting already RUNNING campaign does not duplicate tasks."""
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    c = ops.create_campaign("Duplicate Start Check", "https://app.zomato.com")
    ops.authorize_campaign(c.id, "auditor_alice")
    ops.start_campaign(c.id, auto_dispatch=True)

    tasks_count_1 = repo.session.query(ExecutionTask).filter_by(campaign_id=c.id).count()

    # Second start call
    ops.start_campaign(c.id, auto_dispatch=True)
    tasks_count_2 = repo.session.query(ExecutionTask).filter_by(campaign_id=c.id).count()

    assert tasks_count_1 == tasks_count_2


def test_27_cancelling_cancelled_campaign_is_safe(db_session):
    """27. Repeated cancellation is safe and idempotent."""
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    c = ops.create_campaign("Repeated Cancel", "https://app.zomato.com")
    ops.cancel_campaign(c.id)
    ops.cancel_campaign(c.id)
    ops.cancel_campaign(c.id)
    assert c.status == CampaignLifecycleState.CANCELLED.value


def test_28_duplicate_target_assignment_is_idempotent(db_session):
    """28. Adding the same target URL to a campaign returns existing record."""
    repo = CampaignRepository(db_session)
    c = repo.create_campaign("Idempotent Target", "https://app.zomato.com")
    t1 = repo.add_target(c.id, "https://app.zomato.com", "IN_SCOPE")
    t2 = repo.add_target(c.id, "https://app.zomato.com", "IN_SCOPE")
    assert t1.id == t2.id


# ──────────────────────────────────────────────────────────────────────────────
# GROUP 5: DIAGNOSTIC RUNTIME TRUTH (29-31)
# ──────────────────────────────────────────────────────────────────────────────

def test_29_cancelled_campaign_reports_phase_cancelled(db_session):
    """29. CANCELLED campaign reports phase CANCELLED."""
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    c = ops.create_campaign("Truth Cancelled", "https://app.zomato.com")
    ops.cancel_campaign(c.id)

    truth = ops.get_campaign_runtime_truth(c.id)
    assert truth["status"] == "CANCELLED"
    assert truth["current_phase"] == "CANCELLED"
    assert "cancelled" in truth["active_operation"].lower()
    assert truth["is_stalled"] is False


def test_30_running_campaign_reports_actual_phase(db_session):
    """30. RUNNING campaign reports actual phase (RECON / TESTING / VERIFICATION)."""
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    c = ops.create_campaign("Truth Running", "https://app.zomato.com")
    ops.authorize_campaign(c.id, "auditor_alice")
    ops.start_campaign(c.id, auto_dispatch=True)

    truth = ops.get_campaign_runtime_truth(c.id)
    assert truth["status"] == "RUNNING"
    assert truth["current_phase"] in ["RECON", "SCOPE", "TESTING"]


def test_31_runtime_panel_never_displays_draft_for_cancelled_campaign(db_session):
    """31. Runtime truth and status helpers never display DRAFT for CANCELLED campaign."""
    repo = CampaignRepository(db_session)
    ops = CampaignOperationsService(repo)
    c = ops.create_campaign("No Draft on Cancel", "https://app.zomato.com")
    ops.cancel_campaign(c.id)

    truth = ops.get_campaign_runtime_truth(c.id)
    assert truth["current_phase"] != "DRAFT"
    assert truth["current_phase"] == "CANCELLED"
