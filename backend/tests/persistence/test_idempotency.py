"""AihaX Phase 8 — Idempotency Protections Unit Tests."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.models.database import Base
from backend.persistence.repository import CampaignRepository


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


def test_idempotent_task_creation(db_session):
    repo = CampaignRepository(db_session)
    campaign = repo.create_campaign(name="Idempotency Test", target_url="http://example.com")

    # Create task with identical parameters twice
    t1 = repo.create_task(
        campaign_id=campaign.id,
        target_url="http://example.com",
        check_id="C023_SQL_Injection",
        endpoint_url="http://example.com/search",
        parameter_name="q",
    )
    t2 = repo.create_task(
        campaign_id=campaign.id,
        target_url="http://example.com",
        check_id="C023_SQL_Injection",
        endpoint_url="http://example.com/search",
        parameter_name="q",
    )
    db_session.commit()

    assert t1.id == t2.id
    counts = repo.count_tasks_by_status(campaign.id)
    assert sum(counts.values()) == 1


def test_idempotent_target_addition(db_session):
    repo = CampaignRepository(db_session)
    campaign = repo.create_campaign(name="Idempotent Target", target_url="http://example.com")

    t1 = repo.add_target(campaign.id, "http://example.com/api", "IN_SCOPE")
    t2 = repo.add_target(campaign.id, "http://example.com/api", "IN_SCOPE")
    db_session.commit()

    assert t1.id == t2.id
    targets = repo.get_targets(campaign.id)
    assert len([t for t in targets if t.normalized_url == "http://example.com/api"]) == 1


def test_idempotent_snapshot_update(db_session):
    repo = CampaignRepository(db_session)
    campaign = repo.create_campaign(name="Idempotent Snapshot", target_url="http://example.com")

    snap1 = repo.save_snapshot(campaign.id, {"version": "1.0", "target": "http://example.com"})
    snap2 = repo.save_snapshot(campaign.id, {"version": "1.0", "target": "http://example.com"})
    db_session.commit()

    assert snap1.id == snap2.id
    assert snap1.snapshot_hash == snap2.snapshot_hash
