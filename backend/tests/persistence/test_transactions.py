"""AihaX Phase 8 — Database Transactions & Rollback Unit Tests."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.models.database import Base
from backend.persistence.repository import CampaignRepository
from backend.persistence.state_machine import CampaignLifecycleState, InvalidStateTransitionError


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


def test_transaction_rollback_on_error(db_session):
    repo = CampaignRepository(db_session)
    campaign = repo.create_campaign(name="Tx Test", target_url="http://example.com")
    db_session.commit()

    try:
        # Attempt an illegal operation and rollback
        repo.update_campaign_status(campaign.id, CampaignLifecycleState.COMPLETED)
        db_session.commit()
    except InvalidStateTransitionError:
        db_session.rollback()

    # Verify status is still DRAFT after rollback
    fetched = repo.get_campaign(campaign.id)
    assert fetched.status == CampaignLifecycleState.DRAFT.value
