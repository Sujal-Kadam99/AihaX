"""AihaX Phase 8 — Campaign Cryptographic Manifest Unit Tests."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.evidence.evidence_manifest import ManifestBuilder
from backend.evidence.evidence_store import EvidenceVault
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


def test_build_and_verify_campaign_manifest(db_session):
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)
    vault = EvidenceVault(repo)

    campaign = service.create_campaign(
        name="Manifest Test",
        target_url="http://example.com",
        mode="SAFE_SCAN",
    )
    service.authorize_campaign(campaign.id, "auditor_alice")
    vault.store_evidence(campaign.id, "REQ", "http://example.com", raw_request="GET / HTTP/1.1")
    vault.store_evidence(campaign.id, "RESP", "http://example.com", raw_response="HTTP/1.1 200 OK")
    db_session.commit()

    # Generate manifest
    manifest = service.generate_manifest(campaign.id)
    assert manifest.manifest_hash is not None
    assert len(manifest.manifest_hash) == 64
    assert len(manifest.evidence_hashes) == 2

    # Verify campaign integrity
    report = service.verify_campaign_integrity(campaign.id)
    assert report.verified is True
    assert len(report.issues) == 0


def test_tampered_evidence_fails_manifest_verification(db_session):
    repo = CampaignRepository(db_session)
    service = CampaignOperationsService(repo)
    vault = EvidenceVault(repo)

    campaign = service.create_campaign(name="Tamper Manifest Test", target_url="http://example.com")
    service.authorize_campaign(campaign.id, "auditor_alice")
    ev = vault.store_evidence(campaign.id, "REQ", "http://example.com", raw_request="GET / HTTP/1.1")
    db_session.commit()

    # Directly tamper with stored evidence record in database
    from backend.persistence.models import EvidenceRecord
    rec = db_session.query(EvidenceRecord).filter(EvidenceRecord.id == ev.id).first()
    rec.sanitized_request = "GET /injected_tampered HTTP/1.1"  # Modifying text without updating hash
    db_session.commit()

    report = service.verify_campaign_integrity(campaign.id)
    assert report.verified is False
    assert any("corrupted" in issue.lower() or "mismatch" in issue.lower() for issue in report.issues)
