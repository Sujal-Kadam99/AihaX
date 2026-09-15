"""AihaX Phase 8 — Configuration & Registry Snapshot Unit Tests."""

import hashlib
import json
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.core.check_registry import registry
from backend.models.database import Base
from backend.persistence.repository import CampaignRepository
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


def test_campaign_snapshot_created_on_creation(db_session):
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)

    campaign = service.create_campaign(
        name="Snapshot Test",
        target_url="http://127.0.0.1:8000",
        mode="SAFE_SCAN",
        in_scope_assets=["http://127.0.0.1:8000", "http://127.0.0.1:8000/api"],
    )
    db_session.commit()

    snapshot = repo.get_snapshot(campaign.id)
    assert snapshot is not None
    assert snapshot.campaign_id == campaign.id
    assert snapshot.snapshot_hash is not None

    data = json.loads(snapshot.snapshot_json)
    assert data["target_url"] == "http://127.0.0.1:8000"
    assert "http://127.0.0.1:8000" in data["scope_assets"]
    assert "registry_hash" in data
    assert data["budgets"]["campaign"] == 500


def test_registry_metadata_stable(db_session):
    meta1 = registry.get_registry_metadata()
    meta2 = registry.get_registry_metadata()

    assert meta1["registry_version"] == "1.0.0"
    assert meta1["check_count"] == 77
    assert meta1["registry_hash"] == meta2["registry_hash"]
    assert meta1["contract_hash"] == meta2["contract_hash"]
