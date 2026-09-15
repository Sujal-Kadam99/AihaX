"""AihaX Phase 8 — Mandatory Authorization Gating Unit Tests."""

import pytest
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.models.database import Base
from backend.persistence.repository import CampaignRepository
from backend.services.campaign_operations import (
    AuthorizationRequiredException,
    CampaignOperationsService,
    ScopeMismatchException,
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


def test_unauthorized_campaign_cannot_start(db_session):
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)

    campaign = service.create_campaign(name="Unauthorized Test", target_url="http://example.com")
    db_session.commit()

    # Attempting to start without authorization must fail closed
    with pytest.raises(AuthorizationRequiredException):
        service.start_campaign(campaign.id)


def test_expired_authorization_blocks_execution(db_session):
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)

    campaign = service.create_campaign(name="Expired Auth Test", target_url="http://example.com")
    service.authorize_campaign(campaign.id, "auditor_bob")

    # Manually expire the authorization in the database
    auth = repo.get_authorization(campaign.id)
    auth.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db_session.commit()

    with pytest.raises(AuthorizationRequiredException) as excinfo:
        service.start_campaign(campaign.id)
    assert "expired" in str(excinfo.value).lower()


def test_scope_mutation_after_authorization_blocks_execution(db_session):
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)

    campaign = service.create_campaign(name="Scope Mismatch Test", target_url="http://example.com")
    service.authorize_campaign(campaign.id, "auditor_alice")
    db_session.commit()

    # Infiltrate a new out-of-scope target after authorization was signed
    repo.add_target(campaign.id, "http://unauthorized-evil.com", "IN_SCOPE")
    db_session.commit()

    # Execution must detect scope_hash mismatch and fail closed
    with pytest.raises(ScopeMismatchException):
        service.start_campaign(campaign.id)
