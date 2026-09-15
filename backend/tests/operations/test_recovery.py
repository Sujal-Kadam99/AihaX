"""AihaX Phase 8 — Process Crash Simulation & Resumption Tests."""

import pytest
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.models.database import Base
from backend.persistence.repository import CampaignRepository
from backend.persistence.state_machine import CampaignLifecycleState, TaskLifecycleState
from backend.services.campaign_operations import CampaignOperationsService


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


def test_crash_recovery_resumes_campaign(db_session):
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)

    campaign = service.create_campaign(name="Crash Recovery Test", target_url="http://example.com")
    service.authorize_campaign(campaign.id, "auditor_alice")
    service.start_campaign(campaign.id)

    # Worker 1 claims task and crashes (simulated lease timeout)
    t = repo.create_task(campaign.id, "http://example.com", "C023", "http://example.com/search")
    claimed = service.claim_tasks_for_worker(campaign.id, "worker_dead", limit=1, lease_seconds=10)
    assert len(claimed) == 1

    # Simulate time passing beyond lease expiry
    t.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=100)
    db_session.commit()

    # Recovery coordinator runs
    recovered = service.recover_stale_tasks(campaign.id)
    assert len(recovered) == 1
    assert recovered[0].id == t.id
    assert recovered[0].status == TaskLifecycleState.RETRY_PENDING.value

    # Worker 2 claims the recovered task and completes it
    new_claimed = service.claim_tasks_for_worker(campaign.id, "worker_alive", limit=1)
    assert len(new_claimed) == 1
    assert new_claimed[0].id == t.id

    repo.complete_task(t.id, "worker_alive")
    assert t.status == TaskLifecycleState.COMPLETED.value
