"""AihaX Phase 8 — Campaign Pause and Resume Operations Tests."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.models.database import Base
from backend.persistence.repository import CampaignRepository
from backend.persistence.state_machine import CampaignLifecycleState
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


def test_pause_and_resume_campaign(db_session):
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)

    campaign = service.create_campaign(name="Pause Test", target_url="http://example.com")
    service.authorize_campaign(campaign.id, "auditor_alice")
    service.start_campaign(campaign.id)

    # Pause campaign
    service.pause_campaign(campaign.id, actor="alice", reason="Maintenance window")
    c_paused = repo.get_campaign(campaign.id)
    assert c_paused.status == CampaignLifecycleState.PAUSED.value

    # Workers cannot claim tasks while campaign is PAUSED
    repo.create_task(campaign.id, "http://example.com", "C001_Open_Port", "http://example.com/api")
    claimed_while_paused = service.claim_tasks_for_worker(campaign.id, "worker_1")
    assert len(claimed_while_paused) == 0

    # Resume campaign
    service.resume_campaign(campaign.id, actor="alice")
    c_resumed = repo.get_campaign(campaign.id)
    assert c_resumed.status == CampaignLifecycleState.RUNNING.value

    # Workers can claim tasks now
    claimed_after_resume = service.claim_tasks_for_worker(campaign.id, "worker_1")
    assert len(claimed_after_resume) == 1
