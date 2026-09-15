"""AihaX Phase 8 — Task Queue, Atomic Leases & Recovery Unit Tests."""

import pytest
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.models.database import Base
from backend.persistence.models import ExecutionTask
from backend.persistence.repository import CampaignRepository
from backend.persistence.state_machine import TaskLifecycleState


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


def test_create_and_claim_task(db_session):
    repo = CampaignRepository(db_session)
    campaign = repo.create_campaign(name="Task Test", target_url="http://example.com")
    task = repo.create_task(
        campaign_id=campaign.id,
        target_url="http://example.com",
        check_id="C001_Open_Port",
        endpoint_url="http://example.com/api",
    )
    db_session.commit()

    assert task.status == TaskLifecycleState.PENDING.value
    assert task.attempt_count == 0
    assert task.worker_id is None

    # Claim task under worker_1
    claimed = repo.claim_tasks(campaign.id, worker_id="worker_1", limit=1, lease_duration_seconds=60)
    assert len(claimed) == 1
    assert claimed[0].id == task.id
    assert claimed[0].worker_id == "worker_1"
    assert claimed[0].status == TaskLifecycleState.CLAIMED.value
    assert claimed[0].attempt_count == 1
    assert claimed[0].lease_expires_at is not None


def test_concurrent_worker_cannot_claim_same_task(db_session):
    repo = CampaignRepository(db_session)
    campaign = repo.create_campaign(name="Lock Test", target_url="http://example.com")
    repo.create_task(
        campaign_id=campaign.id,
        target_url="http://example.com",
        check_id="C023_SQL_Injection",
        endpoint_url="http://example.com/search",
    )
    db_session.commit()

    # Worker A claims the only task
    claimed_a = repo.claim_tasks(campaign.id, worker_id="worker_A", limit=5)
    assert len(claimed_a) == 1

    # Worker B tries to claim tasks — should receive 0
    claimed_b = repo.claim_tasks(campaign.id, worker_id="worker_B", limit=5)
    assert len(claimed_b) == 0


def test_renew_task_lease(db_session):
    repo = CampaignRepository(db_session)
    campaign = repo.create_campaign(name="Renew Test", target_url="http://example.com")
    task = repo.create_task(
        campaign_id=campaign.id,
        target_url="http://example.com",
        check_id="C037_Reflected_XSS",
        endpoint_url="http://example.com/search",
    )
    repo.claim_tasks(campaign.id, worker_id="worker_1", limit=1, lease_duration_seconds=30)
    db_session.commit()

    # Renew lease
    success = repo.renew_task_lease(task.id, worker_id="worker_1", lease_duration_seconds=120)
    assert success is True

    # Other worker cannot renew
    fail = repo.renew_task_lease(task.id, worker_id="wrong_worker", lease_duration_seconds=120)
    assert fail is False


def test_complete_task(db_session):
    repo = CampaignRepository(db_session)
    campaign = repo.create_campaign(name="Complete Test", target_url="http://example.com")
    task = repo.create_task(
        campaign_id=campaign.id,
        target_url="http://example.com",
        check_id="C023_SQL_Injection",
        endpoint_url="http://example.com/search",
    )
    repo.claim_tasks(campaign.id, worker_id="worker_1", limit=1)

    completed = repo.complete_task(task.id, worker_id="worker_1")
    assert completed.status == TaskLifecycleState.COMPLETED.value
    assert completed.completed_at is not None
    assert completed.lease_expires_at is None


def test_fail_task_with_retries(db_session):
    repo = CampaignRepository(db_session)
    campaign = repo.create_campaign(name="Fail Test", target_url="http://example.com")
    task = repo.create_task(
        campaign_id=campaign.id,
        target_url="http://example.com",
        check_id="C026_OS_Command_Injection",
        endpoint_url="http://example.com/exec",
    )
    repo.claim_tasks(campaign.id, worker_id="worker_1", limit=1)

    # Attempt 1 fails -> RETRY_PENDING
    failed_1 = repo.fail_task(task.id, worker_id="worker_1", reason="Socket timeout", can_retry=True)
    assert failed_1.status == TaskLifecycleState.RETRY_PENDING.value
    assert failed_1.attempt_count == 1

    # Claim again (attempt 2)
    repo.claim_tasks(campaign.id, worker_id="worker_2", limit=1)
    failed_2 = repo.fail_task(task.id, worker_id="worker_2", reason="Socket timeout", can_retry=True)
    assert failed_2.status == TaskLifecycleState.RETRY_PENDING.value
    assert failed_2.attempt_count == 2

    # Claim again (attempt 3) and fail -> reaches max retries (3) -> FAILED
    repo.claim_tasks(campaign.id, worker_id="worker_3", limit=1)
    failed_3 = repo.fail_task(task.id, worker_id="worker_3", reason="Socket timeout", can_retry=True)
    assert failed_3.status == TaskLifecycleState.FAILED.value
    assert failed_3.completed_at is not None


def test_recover_stale_tasks(db_session):
    repo = CampaignRepository(db_session)
    campaign = repo.create_campaign(name="Stale Recovery Test", target_url="http://example.com")
    task = repo.create_task(
        campaign_id=campaign.id,
        target_url="http://example.com",
        check_id="C023_SQL_Injection",
        endpoint_url="http://example.com/search",
    )
    repo.claim_tasks(campaign.id, worker_id="crashed_worker", limit=1, lease_duration_seconds=10)

    # Simulate lease expiry in the past
    task.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=60)
    db_session.commit()

    # Recovery process finds and resets the task
    recovered = repo.recover_stale_tasks(campaign.id)
    assert len(recovered) == 1
    assert recovered[0].id == task.id
    assert recovered[0].status == TaskLifecycleState.RETRY_PENDING.value
    assert recovered[0].worker_id is None
    assert recovered[0].lease_expires_at is None
