"""AihaX Phase 8 — Campaign Persistence Unit Tests."""

import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.models.database import Base
from backend.persistence.models import Campaign, CampaignTarget, ExecutionTask, AuthorizationRecord
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


def test_create_and_get_campaign(db_session):
    repo = CampaignRepository(db_session)
    campaign = repo.create_campaign(
        name="Test Campaign 1",
        target_url="http://127.0.0.1:8080",
        mode="SAFE_SCAN",
        campaign_budget=300,
        target_budget=50,
        check_budget=10,
    )
    db_session.commit()

    assert campaign.id is not None
    assert campaign.name == "Test Campaign 1"
    assert campaign.target_url == "http://127.0.0.1:8080"
    assert campaign.status == CampaignLifecycleState.DRAFT.value
    assert campaign.campaign_budget == 300

    fetched = repo.get_campaign(campaign.id)
    assert fetched is not None
    assert fetched.id == campaign.id
    assert fetched.name == "Test Campaign 1"


def test_campaign_targets_persistence(db_session):
    repo = CampaignRepository(db_session)
    campaign = repo.create_campaign(name="Target Test", target_url="http://example.com")
    t1 = repo.add_target(campaign.id, "http://example.com", "IN_SCOPE")
    t2 = repo.add_target(campaign.id, "http://api.example.com", "IN_SCOPE")
    # Duplicate target should return existing
    t3 = repo.add_target(campaign.id, "http://example.com", "IN_SCOPE")
    db_session.commit()

    assert t3.id == t1.id
    targets = repo.get_targets(campaign.id)
    assert len(targets) == 2
    urls = {t.normalized_url for t in targets}
    assert "http://example.com" in urls
    assert "http://api.example.com" in urls


def test_campaign_status_updates(db_session):
    repo = CampaignRepository(db_session)
    campaign = repo.create_campaign(name="Status Test", target_url="http://example.com")
    repo.create_authorization(campaign.id, "auditor_alice", "scope_hash_123")

    # DRAFT -> AUTHORIZED
    repo.update_campaign_status(campaign.id, CampaignLifecycleState.AUTHORIZED)
    assert repo.get_campaign(campaign.id).status == "AUTHORIZED"

    # AUTHORIZED -> RUNNING
    repo.update_campaign_status(campaign.id, CampaignLifecycleState.RUNNING)
    c_running = repo.get_campaign(campaign.id)
    assert c_running.status == "RUNNING"
    assert c_running.started_at is not None

    # RUNNING -> PAUSED
    repo.update_campaign_status(campaign.id, CampaignLifecycleState.PAUSED)
    c_paused = repo.get_campaign(campaign.id)
    assert c_paused.status == "PAUSED"
    assert c_paused.paused_at is not None

    # PAUSED -> RUNNING
    repo.update_campaign_status(campaign.id, CampaignLifecycleState.RUNNING)
    assert repo.get_campaign(campaign.id).status == "RUNNING"

    # RUNNING -> COMPLETED
    repo.update_campaign_status(campaign.id, CampaignLifecycleState.COMPLETED)
    c_done = repo.get_campaign(campaign.id)
    assert c_done.status == "COMPLETED"
    assert c_done.completed_at is not None


def test_invalid_status_transition_raises(db_session):
    repo = CampaignRepository(db_session)
    campaign = repo.create_campaign(name="Invalid Test", target_url="http://example.com")

    # DRAFT -> COMPLETED is invalid (skipping AUTHORIZED and RUNNING)
    with pytest.raises(InvalidStateTransitionError):
        repo.update_campaign_status(campaign.id, CampaignLifecycleState.COMPLETED)


def test_campaign_audit_trail_chained_hashes(db_session):
    repo = CampaignRepository(db_session)
    campaign = repo.create_campaign(name="Audit Test", target_url="http://example.com")
    repo.create_authorization(campaign.id, "alice", "scope_123")
    repo.update_campaign_status(campaign.id, CampaignLifecycleState.AUTHORIZED)
    db_session.commit()

    events = repo.get_audit_trail(campaign.id)
    assert len(events) >= 3

    # Check that event_hashes are chained
    prev_hash = None
    for ev in events:
        assert ev.event_hash is not None
        assert len(ev.event_hash) == 64
        assert ev.previous_event_hash == prev_hash
        prev_hash = ev.event_hash
