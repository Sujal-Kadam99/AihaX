"""AihaX Phase 8 — Evidence Store Unit Tests."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.evidence.evidence_store import EvidenceVault
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


def test_store_and_retrieve_evidence(db_session):
    repo = CampaignRepository(db_session)
    campaign = repo.create_campaign(name="Vault Test", target_url="http://example.com")
    vault = EvidenceVault(repo)

    entry = vault.store_evidence(
        campaign_id=campaign.id,
        evidence_type="PROOF",
        target_url="http://example.com/search",
        method="GET",
        raw_request="GET /search?q=test HTTP/1.1\nHost: example.com",
        raw_response="HTTP/1.1 200 OK\n\nSearch results for test",
        payload_summary="test",
    )
    db_session.commit()

    assert entry.id is not None
    assert entry.content_hash is not None
    assert len(entry.content_hash) == 64
    assert entry.chain_hash is not None
    assert len(entry.chain_hash) == 64

    fetched = vault.get_evidence(entry.id)
    assert fetched is not None
    assert fetched.id == entry.id
    assert fetched.target_url == "http://example.com/search"


def test_evidence_secrets_redacted_before_persistence(db_session):
    repo = CampaignRepository(db_session)
    campaign = repo.create_campaign(name="Redaction Vault Test", target_url="http://example.com")
    vault = EvidenceVault(repo)

    raw_req = "GET /user HTTP/1.1\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak\nCookie: session=super_secret_cookie_123"
    entry = vault.store_evidence(
        campaign_id=campaign.id,
        evidence_type="REQUEST",
        target_url="http://example.com/user",
        raw_request=raw_req,
    )
    db_session.commit()

    assert "do_not_leak" not in entry.sanitized_request
    assert "[REDACTED-JWT]" in entry.sanitized_request or "[REDACTED]" in entry.sanitized_request
    assert "super_secret_cookie_123" not in entry.sanitized_request


def test_vault_integrity_verification_passes(db_session):
    repo = CampaignRepository(db_session)
    campaign = repo.create_campaign(name="Vault Integrity Test", target_url="http://example.com")
    vault = EvidenceVault(repo)

    vault.store_evidence(campaign.id, "REQ", "http://example.com", raw_request="GET / HTTP/1.1")
    vault.store_evidence(campaign.id, "RESP", "http://example.com", raw_response="HTTP/1.1 200 OK")
    db_session.commit()

    valid, issues = vault.verify_vault_integrity(campaign.id)
    assert valid is True
    assert len(issues) == 0
