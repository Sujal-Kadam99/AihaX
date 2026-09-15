"""Unit & Integration tests for Phase 5.1-A Passive Recon Database Foundation."""

import json
import pytest
import uuid
from datetime import datetime, timezone
from sqlalchemy import create_engine, text, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from backend.models.database import (
    Base,
    Program,
    ProgramScope,
    DiscoverySource,
    Asset,
    AssetObservation,
    Endpoint,
    TechnologyFingerprint,
    get_utc_now,
)
from backend.models.migrations import run_migrations, MIGRATIONS


@pytest.fixture
def memory_db():
    engine = create_engine("sqlite:///:memory:")
    
    # Enforce SQLite foreign keys
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

    # Run all versioned migrations (including 015)
    run_migrations(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    engine.dispose()


def test_015_migration_applied(memory_db):
    """Test that migration 15 applied cleanly and all tables exist."""
    session = memory_db
    rows = session.execute(text("SELECT version, name FROM schema_migrations ORDER BY version ASC")).fetchall()
    versions = [r[0] for r in rows]
    names = [r[1] for r in rows]

    assert 15 in versions
    assert "015_passive_asset_discovery" in names

    # Verify tables exist in SQLite master
    tables = [
        r[0] for r in session.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()
    ]
    assert "discovery_sources" in tables
    assert "assets" in tables
    assert "asset_observations" in tables
    assert "endpoints" in tables
    assert "technology_fingerprints" in tables


def test_security_invariant_discovered_not_authorized_defaults(memory_db):
    """SECURITY INVARIANT: Every newly created/discovered asset MUST default to UNKNOWN and NOT authorized."""
    session = memory_db

    program = Program(name="HackerOne Program")
    session.add(program)
    session.commit()

    asset = Asset(
        program_id=program.id,
        asset_type="SUBDOMAIN",
        normalized_value="api.example.com",
    )
    session.add(asset)
    session.commit()
    session.refresh(asset)

    # Invariant checks
    assert asset.scope_status == "UNKNOWN"
    assert asset.active_testing_allowed is False
    assert asset.authorization_confirmed is False

    # Verify gate: active_testing_allowed should only be True if IN_SCOPE and authorization_confirmed
    def can_allow_active_testing(a: Asset) -> bool:
        return a.scope_status == "IN_SCOPE" and a.authorization_confirmed is True

    assert can_allow_active_testing(asset) is False

    # Transition to IN_SCOPE without authorization confirmation
    asset.scope_status = "IN_SCOPE"
    session.commit()
    assert can_allow_active_testing(asset) is False

    # Transition to authorization_confirmed = True
    asset.authorization_confirmed = True
    asset.active_testing_allowed = True
    session.commit()
    assert can_allow_active_testing(asset) is True


def test_asset_relationships_and_cascades(memory_db):
    """Test relationships across Program -> Asset -> Observations, Endpoints, Technologies."""
    session = memory_db

    # 1. Create Program
    program = Program(name="Bugcrowd Target Program")
    session.add(program)
    session.commit()

    # 2. Create DiscoverySource
    src_crtsh = DiscoverySource(
        source_code="SRC_CRTSH",
        name="crt.sh Certificate Transparency",
        description="Passive CT logs",
        enabled=True,
    )
    src_wayback = DiscoverySource(
        source_code="SRC_WAYBACK",
        name="Wayback Machine CDX API",
        description="Historical archive scraping",
        enabled=True,
    )
    session.add_all([src_crtsh, src_wayback])
    session.commit()

    # 3. Create Asset
    asset = Asset(
        program_id=program.id,
        asset_type="DOMAIN",
        normalized_value="example.com",
        dns_records=json.dumps({"A": ["93.184.216.34"]}),
    )
    session.add(asset)
    session.commit()

    # 4. Create Observation
    obs = AssetObservation(
        asset_id=asset.id,
        source_id=src_crtsh.id,
        request_id="REQ-CRT-001",
        evidence_id="EVD-RECON-001",
        raw_data=json.dumps({"san": "example.com"}),
        confidence=95,
    )
    session.add(obs)

    # 5. Create Endpoint
    ep = Endpoint(
        program_id=program.id,
        asset_id=asset.id,
        normalized_url="https://example.com/api/v1/users",
        path="/api/v1/users",
        query_parameters=json.dumps(["page", "limit"]),
        source_id=src_wayback.id,
    )
    session.add(ep)

    # 6. Create TechnologyFingerprint
    tech = TechnologyFingerprint(
        asset_id=asset.id,
        technology="Nginx",
        version="1.24.0",
        detection_rule="Header: Server",
        source_id=src_wayback.id,
        confidence=90,
    )
    session.add(tech)
    session.commit()

    # 7. Verify bidirectional ORM navigation
    session.refresh(program)
    assert len(program.assets) == 1
    assert program.assets[0].normalized_value == "example.com"
    assert len(program.endpoints) == 1
    assert program.endpoints[0].path == "/api/v1/users"

    session.refresh(asset)
    assert len(asset.observations) == 1
    assert asset.observations[0].evidence_id == "EVD-RECON-001"
    assert asset.observations[0].source.source_code == "SRC_CRTSH"
    assert len(asset.endpoints) == 1
    assert len(asset.technologies) == 1
    assert asset.technologies[0].technology == "Nginx"

    # 8. Test Cascade Delete: deleting Program deletes Asset, Observations, Endpoints, Technologies
    session.delete(program)
    session.commit()

    assert session.query(Asset).filter_by(id=asset.id).first() is None
    assert session.query(AssetObservation).filter_by(id=obs.id).first() is None
    assert session.query(Endpoint).filter_by(id=ep.id).first() is None
    assert session.query(TechnologyFingerprint).filter_by(id=tech.id).first() is None
    # DiscoverySource is NOT deleted on program deletion
    assert session.query(DiscoverySource).filter_by(id=src_crtsh.id).first() is not None


def test_asset_unique_constraint(memory_db):
    """Test unique constraint on (program_id, asset_type, normalized_value)."""
    session = memory_db

    prog = Program(name="Prog Unique Test")
    session.add(prog)
    session.commit()

    a1 = Asset(
        program_id=prog.id,
        asset_type="SUBDOMAIN",
        normalized_value="auth.example.com",
    )
    session.add(a1)
    session.commit()

    # Duplicate asset in same program must raise IntegrityError
    a2 = Asset(
        program_id=prog.id,
        asset_type="SUBDOMAIN",
        normalized_value="auth.example.com",
    )
    session.add(a2)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_endpoint_unique_constraint(memory_db):
    """Test unique constraint on (asset_id, normalized_url)."""
    session = memory_db

    prog = Program(name="Prog Endpoint Test")
    session.add(prog)
    session.commit()

    asset = Asset(
        program_id=prog.id,
        asset_type="DOMAIN",
        normalized_value="target.com",
    )
    session.add(asset)
    session.commit()

    ep1 = Endpoint(
        program_id=prog.id,
        asset_id=asset.id,
        normalized_url="https://target.com/login",
        path="/login",
    )
    session.add(ep1)
    session.commit()

    # Duplicate endpoint for same asset must raise IntegrityError
    ep2 = Endpoint(
        program_id=prog.id,
        asset_id=asset.id,
        normalized_url="https://target.com/login",
        path="/login",
    )
    session.add(ep2)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_discovery_source_code_unique_constraint(memory_db):
    """Test unique constraint on discovery_sources.source_code."""
    session = memory_db

    src1 = DiscoverySource(source_code="SRC_UNIQUE_1", name="Source 1")
    session.add(src1)
    session.commit()

    src2 = DiscoverySource(source_code="SRC_UNIQUE_1", name="Source 1 Duplicate")
    session.add(src2)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
