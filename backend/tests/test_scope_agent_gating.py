"""Regression tests proving ScopeAgent blocks scans when unauthorized or out-of-scope."""

import json
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.agents.scope_agent import ScopeAgent
from backend.models.database import Base, Program, ProgramScope, Scan, ScanConfig
from backend.models.migrations import run_migrations


@pytest.fixture(name="db")
def fixture_db(tmp_path):
    db_file = tmp_path / "test_scope_gating.db"
    db_url = f"sqlite:///{db_file}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    run_migrations(engine, str(db_file))

    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.mark.asyncio
async def test_scope_agent_blocks_when_authorization_not_confirmed(db):
    scan_id = "scan-unauth-test"
    scan = Scan(id=scan_id, target_url="https://example.com", status="pending")
    db.add(scan)
    db.commit()

    agent = ScopeAgent(
        scan_id=scan_id,
        db=db,
        config={
            "target_url": "https://example.com",
            "authorization_confirmed": False,  # Missing authorization!
            "scope_notes": "Valid notes",
        },
    )

    with pytest.raises(ValueError, match="Authorization confirmation is required"):
        await agent.execute()


@pytest.mark.asyncio
async def test_scope_agent_blocks_when_target_is_out_of_scope(db):
    scan_id = "scan-out-of-scope-test"
    prog_id = "prog-test-123"

    # Create program with strict scope
    prog = Program(id=prog_id, name="Strict Program")
    prog_scope = ProgramScope(
        id="scope-123",
        program_id=prog_id,
        in_scope_assets=json.dumps(["*.example.com"]),
        out_of_scope_assets=json.dumps(["admin.example.com"]),
    )
    scan = Scan(id=scan_id, target_url="https://admin.example.com", status="pending", program_id=prog_id)
    db.add_all([prog, prog_scope, scan])
    db.commit()

    agent = ScopeAgent(
        scan_id=scan_id,
        db=db,
        config={
            "target_url": "https://admin.example.com",
            "program_id": prog_id,
            "authorization_confirmed": True,
            "scope_notes": "Authorized scope",
        },
    )

    with pytest.raises(ValueError, match="Scope violation"):
        await agent.execute()

    # Scan status must be updated to failed in database
    db.refresh(scan)
    assert scan.status == "failed"


@pytest.mark.asyncio
async def test_scope_agent_passes_when_target_is_authorized_and_in_scope(db):
    scan_id = "scan-success-test"
    prog_id = "prog-test-456"

    prog = Program(id=prog_id, name="Allowed Program")
    prog_scope = ProgramScope(
        id="scope-456",
        program_id=prog_id,
        in_scope_assets=json.dumps(["*.example.com", "example.com"]),
        out_of_scope_assets=json.dumps(["admin.example.com"]),
    )
    scan = Scan(id=scan_id, target_url="https://api.example.com", status="pending", program_id=prog_id)
    db.add_all([prog, prog_scope, scan])
    db.commit()

    agent = ScopeAgent(
        scan_id=scan_id,
        db=db,
        config={
            "target_url": "https://api.example.com",
            "program_id": prog_id,
            "authorization_confirmed": True,
            "scope_notes": "Authorized scope",
        },
    )

    result = await agent.execute()
    assert result["authorization_confirmed"] is True
    assert result["scope_decision"]["allowed"] is True

    db.refresh(scan)
    assert scan.status == "running"
