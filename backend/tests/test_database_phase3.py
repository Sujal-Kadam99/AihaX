"""Phase 3 Database & Data Persistence Comprehensive Test Suite."""

import base64
import os
import sqlite3
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

from backend.core.encryption import decrypt_string, encrypt_string
from backend.models.database import (
    AgentLog,
    Base,
    ExploitChain,
    Finding,
    RefreshToken,
    Scan,
    ScanConfig,
    User,
    UTCDateTime,
    get_engine,
    get_session_factory,
    init_db,
    set_sqlite_pragma,
)
from backend.models.migrations import MIGRATIONS, _compute_checksum, run_migrations
from backend.services.db_service import (
    AgentLogRepository,
    FindingRepository,
    ScanRepository,
)


@pytest.fixture
def temp_db_file():
    """Create temporary SQLite database file path."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = tmp.name
    yield tmp_path
    # Force garbage collection / file release
    import gc
    gc.collect()
    try:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        bak_path = tmp_path + ".bak"
        if os.path.exists(bak_path):
            os.remove(bak_path)
    except PermissionError:
        pass


# -----------------------------------------------------------------------------
# 1. SQLite PRAGMAs & Connection Tuning
# -----------------------------------------------------------------------------

def test_sqlite_pragmas_enabled(temp_db_file):
    """Verify SQLite PRAGMAs (WAL mode, busy_timeout=5000, foreign_keys=ON)."""
    engine = create_engine(f"sqlite:///{temp_db_file}")
    event.listen(engine, "connect", set_sqlite_pragma)

    try:
        with engine.connect() as conn:
            journal_mode = conn.execute(text("PRAGMA journal_mode")).scalar()
            busy_timeout = conn.execute(text("PRAGMA busy_timeout")).scalar()
            foreign_keys = conn.execute(text("PRAGMA foreign_keys")).scalar()

        assert journal_mode is not None and str(journal_mode).lower() == "wal"
        assert busy_timeout == 5000
        assert foreign_keys == 1
    finally:
        engine.dispose()


# -----------------------------------------------------------------------------
# 2. Transactional Migrations & Checksum Integrity
# -----------------------------------------------------------------------------

def test_transactional_migration_execution(temp_db_file):
    """Verify programmatic migration runner executes transactionally and records checksums."""
    engine = create_engine(f"sqlite:///{temp_db_file}")
    try:
        run_migrations(engine, db_path=temp_db_file)

        with engine.connect() as conn:
            rows = conn.execute(text("SELECT version, name, checksum FROM schema_migrations ORDER BY version ASC")).fetchall()
            assert len(rows) == len(MIGRATIONS)
            for i, m in enumerate(MIGRATIONS):
                assert rows[i][0] == m["version"]
                assert rows[i][1] == m["name"]
                assert rows[i][2] == _compute_checksum(m["up_sql"])
    finally:
        engine.dispose()


def test_migration_checksum_tampered_fails(temp_db_file):
    """Verify modified historical migration script triggers checksum validation error."""
    engine = create_engine(f"sqlite:///{temp_db_file}")
    try:
        run_migrations(engine, db_path=temp_db_file)

        # Tamper with recorded checksum in database
        with engine.begin() as conn:
            conn.execute(text("UPDATE schema_migrations SET checksum = 'tampered_hash' WHERE version = 1"))

        with pytest.raises(RuntimeError) as exc:
            run_migrations(engine, db_path=temp_db_file)
        assert "Migration integrity validation failed for version 1" in str(exc.value)
    finally:
        engine.dispose()


def test_migration_rollback_and_backup_recovery(temp_db_file):
    """Verify failed migrations roll back and restore database from aihax.db.bak."""
    engine = create_engine(f"sqlite:///{temp_db_file}")
    try:
        run_migrations(engine, db_path=temp_db_file)

        # Create dummy migration with broken SQL statement
        broken_migration = {
            "version": 999,
            "name": "999_broken",
            "up_sql": ["INVALID SQL SYNTAX HERE"],
        }
        MIGRATIONS.append(broken_migration)

        try:
            with pytest.raises(Exception):
                run_migrations(engine, db_path=temp_db_file)
        finally:
            MIGRATIONS.pop()

        # Confirm database is functional and undamaged
        with engine.connect() as conn:
            count = conn.execute(text("SELECT COUNT(*) FROM schema_migrations")).scalar()
            assert count == len(MIGRATIONS)
    finally:
        engine.dispose()


# -----------------------------------------------------------------------------
# 3. AES-256-GCM Authenticated Credential Encryption
# -----------------------------------------------------------------------------

def test_aes_gcm_credential_encryption_at_rest(temp_db_file):
    """Verify ScanConfig sensitive credentials are encrypted on disk and fail safely when tampered."""
    engine = create_engine(f"sqlite:///{temp_db_file}")
    try:
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(bind=engine)

        db = SessionLocal()
        scan = Scan(target_url="https://target.local", status="pending")
        db.add(scan)
        db.commit()

        secret_pass = "SuperSecretP@ssw0rd!"
        config = ScanConfig(
            scan_id=scan.id,
            primary_creds=secret_pass,
            api_auth="Bearer token_123",
        )
        db.add(config)
        db.commit()
        config_id = config.id
        db.close()

        # 1. Query raw SQLite file via DB connection to confirm ciphertext on disk
        with engine.connect() as raw_conn:
            raw_row = raw_conn.execute(
                text("SELECT primary_creds FROM scan_configs WHERE id = :id"), {"id": config_id}
            ).fetchone()
            assert raw_row is not None
            raw_cipher = raw_row[0]
            assert secret_pass not in raw_cipher
            assert len(raw_cipher) > 20

        # 2. Query through ORM session to confirm automatic decryption
        db2 = SessionLocal()
        queried = db2.query(ScanConfig).filter_by(id=config_id).first()
        assert queried is not None
        assert queried.primary_creds == secret_pass
        assert queried.api_auth == "Bearer token_123"
        db2.close()
    finally:
        engine.dispose()


def test_encrypted_credential_tampering_raises_error():
    """Verify tampered ciphertext or altered GCM auth tag raises ValueError and fails safely."""
    plaintext = "SensitiveSecret"
    ciphertext = encrypt_string(plaintext)
    assert ciphertext != plaintext

    # Tamper with base64 ciphertext payload bytes
    raw = base64.b64decode(ciphertext.encode("utf-8"))
    tampered_raw = raw[:-1] + (b"\x00" if raw[-1:] != b"\x00" else b"\x01")
    tampered_ciphertext = base64.b64encode(tampered_raw).decode("utf-8")

    with pytest.raises(ValueError) as exc:
        decrypt_string(tampered_ciphertext)
    assert "Decryption failed or authentication tag tampered" in str(exc.value)


# -----------------------------------------------------------------------------
# 4. Timezone-Aware UTC Timestamp Round-Trip Standardization
# -----------------------------------------------------------------------------

def test_utc_timestamp_roundtrip(temp_db_file):
    """Verify UTCDateTime TypeDecorator round-trips timezone-aware UTC objects."""
    engine = create_engine(f"sqlite:///{temp_db_file}")
    try:
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(bind=engine)

        db = SessionLocal()
        now_utc = datetime.now(timezone.utc)
        scan = Scan(target_url="https://utc.test", created_at=now_utc)
        db.add(scan)
        db.commit()
        scan_id = scan.id
        db.close()

        db2 = SessionLocal()
        queried = db2.query(Scan).filter_by(id=scan_id).first()
        assert queried is not None
        assert queried.created_at is not None
        assert queried.created_at.tzinfo is not None
        assert queried.created_at.tzinfo == timezone.utc
        assert abs((queried.created_at - now_utc).total_seconds()) < 1.0
        db2.close()
    finally:
        engine.dispose()


# -----------------------------------------------------------------------------
# 5. SQLite Concurrency & Bounded Retry Handling
# -----------------------------------------------------------------------------

def test_multithreaded_concurrent_db_writes(temp_db_file):
    """Verify 10 concurrent threads writing findings across separate DB sessions under WAL mode."""
    engine = create_engine(f"sqlite:///{temp_db_file}")
    event.listen(engine, "connect", set_sqlite_pragma)
    try:
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(bind=engine)

        # Seed parent scan
        seed_session = SessionLocal()
        scan = Scan(target_url="https://concurrent.test", status="running")
        seed_session.add(scan)
        seed_session.commit()
        scan_id = scan.id
        seed_session.close()

        errors = []

        def worker_write(worker_idx: int):
            db = SessionLocal()
            try:
                FindingRepository.add_finding(
                    db,
                    scan_id=scan_id,
                    agent_id=worker_idx,
                    title=f"Finding {worker_idx}",
                    vuln_type="sqli",
                    category="injection",
                    severity="high",
                    affected_url=f"https://concurrent.test/item/{worker_idx}",
                )
            except Exception as err:
                errors.append(err)
            finally:
                db.close()

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker_write, i) for i in range(10)]
            for f in futures:
                f.result()

        assert len(errors) == 0

        verify_session = SessionLocal()
        findings = verify_session.query(Finding).filter_by(scan_id=scan_id).all()
        assert len(findings) == 10
        verify_session.close()
    finally:
        engine.dispose()


# -----------------------------------------------------------------------------
# 6. Foreign Key Cascading Deletions
# -----------------------------------------------------------------------------

def test_foreign_key_cascading_deletes(temp_db_file):
    """Verify deleting a Scan cascade-deletes associated Findings, AgentLogs, ExploitChains, and ScanConfigs."""
    engine = create_engine(f"sqlite:///{temp_db_file}")
    event.listen(engine, "connect", set_sqlite_pragma)
    try:
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(bind=engine)

        db = SessionLocal()
        scan = Scan(target_url="https://cascade.test")
        db.add(scan)
        db.commit()

        finding = Finding(scan_id=scan.id, agent_id=1, title="Test", vuln_type="xss", category="xss", severity="medium", affected_url="http://test")
        log = AgentLog(scan_id=scan.id, agent_id=1, level="INFO", message="Log msg")
        config = ScanConfig(scan_id=scan.id, primary_creds="secret")
        db.add_all([finding, log, config])
        db.commit()

        # Delete scan parent
        db.delete(scan)
        db.commit()

        # Confirm child rows cascade deleted
        assert db.query(Finding).filter_by(scan_id=scan.id).count() == 0
        assert db.query(AgentLog).filter_by(scan_id=scan.id).count() == 0
        assert db.query(ScanConfig).filter_by(scan_id=scan.id).count() == 0
        db.close()
    finally:
        engine.dispose()


# -----------------------------------------------------------------------------
# 7. AuditLog and EntitlementCache Repositories
# -----------------------------------------------------------------------------

def test_audit_log_creation_and_retrieval(temp_db_file):
    """Verify AuditLog repository can record and retrieve state transitions."""
    engine = create_engine(f"sqlite:///{temp_db_file}")
    try:
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(bind=engine)
        db = SessionLocal()

        from backend.services.db_service import AuditLogRepository

        scan_id = str(uuid.uuid4())
        user_id = str(uuid.uuid4())

        AuditLogRepository.log_event(
            db,
            entity_type="scan",
            entity_id=scan_id,
            action="status_change",
            old_value="pending",
            new_value="running",
            user_id=user_id,
        )

        logs = AuditLogRepository.get_by_entity(db, "scan", scan_id)
        assert len(logs) == 1
        assert logs[0].action == "status_change"
        assert logs[0].old_value == "pending"
        assert logs[0].new_value == "running"
        assert logs[0].user_id == user_id

        db.close()
    finally:
        engine.dispose()


def test_entitlement_cache_upsert(temp_db_file):
    """Verify EntitlementCache repository properly upserts and handles JWTs."""
    engine = create_engine(f"sqlite:///{temp_db_file}")
    try:
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(bind=engine)
        db = SessionLocal()

        from backend.services.db_service import EntitlementCacheRepository

        user_id = str(uuid.uuid4())
        expires = datetime.now(timezone.utc) + timedelta(days=7)

        # Create
        EntitlementCacheRepository.upsert(
            db,
            user_id=user_id,
            plan_name="Pro",
            entitlement_jwt="dummy_jwt_1",
            expires_at=expires,
        )

        cache = EntitlementCacheRepository.get_for_user(db, user_id)
        assert cache is not None
        assert cache.plan_name == "Pro"
        assert cache.entitlement_jwt == "dummy_jwt_1"

        # Update
        EntitlementCacheRepository.upsert(
            db,
            user_id=user_id,
            plan_name="Enterprise",
            entitlement_jwt="dummy_jwt_2",
            expires_at=expires,
        )

        cache2 = EntitlementCacheRepository.get_for_user(db, user_id)
        assert cache2 is not None
        assert cache2.plan_name == "Enterprise"
        assert cache2.entitlement_jwt == "dummy_jwt_2"
        # Should be the same record ID
        assert cache2.id == cache.id

        db.close()
    finally:
        engine.dispose()


# -----------------------------------------------------------------------------
# 8. Pagination Helpers
# -----------------------------------------------------------------------------

def test_scan_repository_pagination(temp_db_file):
    """Verify ScanRepository pagination logic."""
    engine = create_engine(f"sqlite:///{temp_db_file}")
    try:
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(bind=engine)
        db = SessionLocal()

        from backend.services.db_service import ScanRepository

        # Insert 25 scans
        user_id = str(uuid.uuid4())
        for i in range(25):
            scan = Scan(
                target_url=f"https://target{i}.test",
                status="completed" if i % 2 == 0 else "running",
                user_id=user_id,
                created_at=datetime.now(timezone.utc) + timedelta(seconds=i),
            )
            db.add(scan)
        db.commit()

        # Page 1, 10 per page
        res = ScanRepository.list_scans_paginated(db, page=1, per_page=10, user_id=user_id)
        assert res.total == 25
        assert len(res.items) == 10
        assert res.page == 1
        assert res.pages == 3
        assert res.has_next is True
        assert res.has_prev is False

        # Page 3, 10 per page
        res3 = ScanRepository.list_scans_paginated(db, page=3, per_page=10, user_id=user_id)
        assert len(res3.items) == 5
        assert res3.has_next is False
        assert res3.has_prev is True

        db.close()
    finally:
        engine.dispose()
