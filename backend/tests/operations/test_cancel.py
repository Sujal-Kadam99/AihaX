"""AihaX Phase 8 — Campaign Cancellation Operations Tests."""

import pytest
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


def test_cancel_campaign_aborts_tasks(db_session):
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)

    campaign = service.create_campaign(name="Cancel Test", target_url="http://example.com")
    service.authorize_campaign(campaign.id, "auditor_alice")
    service.start_campaign(campaign.id)

    # Create pending tasks
    t1 = repo.create_task(campaign.id, "http://example.com", "C001", "http://example.com/1")
    t2 = repo.create_task(campaign.id, "http://example.com", "C002", "http://example.com/2")
    db_session.commit()

    # Cancel campaign
    service.cancel_campaign(campaign.id, actor="alice", reason="Scope changed")
    c_cancelled = repo.get_campaign(campaign.id)
    assert c_cancelled.status == CampaignLifecycleState.CANCELLED.value

    # Tasks should be CANCELLED
    assert t1.status == TaskLifecycleState.CANCELLED.value
    assert t2.status == TaskLifecycleState.CANCELLED.value
