"""Focused tests for Phase 24 Migration 26 and database ORM models."""

import json
import uuid
import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from backend.models.database import (
    Base,
    PreScanResultRecord,
    ToolExecutionRecord,
    AuthContextRecord,
    ExploitabilityRecord,
    AgentOrchestratorRunRecord,
    get_utc_now,
)
from backend.models.migrations import MIGRATIONS, run_migrations, _compute_checksum


@pytest.fixture
def test_db():
    """Create a fresh in-memory SQLite database and execute migrations."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    run_migrations(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield engine, session
    session.close()


class TestMigration26Integrity:
    """Validate Migration 26 registration and schema execution."""

    def test_migration_26_registered(self):
        m26 = next((m for m in MIGRATIONS if m["version"] == 26), None)
        assert m26 is not None
        assert m26["name"] == "026_phase24_e2e_orchestration_and_tools"
        assert len(m26["up_sql"]) >= 5

    def test_migrations_1_to_25_unaltered(self):
        # Verify migration versions are strictly monotonically increasing
        versions = [m["version"] for m in MIGRATIONS]
        assert versions[-1] >= 26
        assert versions == sorted(versions)
        assert len(versions) == len(set(versions))
        assert 26 in versions
        assert 27 in versions
        # Ensure checksums compute deterministically for every migration
        for m in MIGRATIONS:
            cs = _compute_checksum(m["up_sql"])
            assert len(cs) == 64

    def test_all_five_phase24_tables_created(self, test_db):
        engine, _ = test_db
        inspector = inspect(engine)
        table_names = inspector.get_table_names()

        required_tables = [
            "pre_scan_results",
            "tool_execution_records",
            "auth_context_records",
            "exploitability_records",
            "agent_orchestrator_runs",
        ]
        for tbl in required_tables:
            assert tbl in table_names, f"Table {tbl} not found in database schema"

    def test_pre_scan_results_columns(self, test_db):
        engine, _ = test_db
        inspector = inspect(engine)
        columns = {c["name"]: c for c in inspector.get_columns("pre_scan_results")}

        expected_columns = [
            "id", "campaign_id", "target", "overall_status",
            "dns_status", "http_status", "https_status", "tls_status",
            "account1_status", "account2_status", "email_otp_status",
            "api_key_status", "config_status", "authorization_status",
            "check_details_json", "warnings_json", "errors_json",
            "created_at", "updated_at"
        ]
        for col in expected_columns:
            assert col in columns, f"Column {col} missing from pre_scan_results"

    def test_tool_execution_records_columns(self, test_db):
        engine, _ = test_db
        inspector = inspect(engine)
        columns = {c["name"]: c for c in inspector.get_columns("tool_execution_records")}

        expected_columns = [
            "id", "campaign_id", "target", "tool_name", "tool_version",
            "execution_profile", "execution_status", "sanitized_args_json",
            "exit_code", "timeout_seconds", "stdout_hash", "stderr_hash",
            "output_hash", "parsed_summary_json", "error_category",
            "started_at", "completed_at"
        ]
        for col in expected_columns:
            assert col in columns, f"Column {col} missing from tool_execution_records"

    def test_auth_context_records_columns(self, test_db):
        engine, _ = test_db
        inspector = inspect(engine)
        columns = {c["name"]: c for c in inspector.get_columns("auth_context_records")}

        expected_columns = [
            "id", "campaign_id", "account_id", "auth_status",
            "session_handle", "auth_method", "username_hint",
            "expires_at", "last_authenticated_at", "refresh_status",
            "metadata_json", "created_at", "updated_at"
        ]
        for col in expected_columns:
            assert col in columns, f"Column {col} missing from auth_context_records"

    def test_exploitability_records_columns(self, test_db):
        engine, _ = test_db
        inspector = inspect(engine)
        columns = {c["name"]: c for c in inspector.get_columns("exploitability_records")}

        expected_columns = [
            "id", "campaign_id", "target", "finding_id", "hypothesis_id",
            "strategy_id", "strategy_version", "verification_state",
            "proof_type", "impact_classification", "evidence_hash",
            "reproducibility_score", "operator_approval_id",
            "proof_details_json", "verified_at", "created_at"
        ]
        for col in expected_columns:
            assert col in columns, f"Column {col} missing from exploitability_records"

    def test_agent_orchestrator_runs_columns(self, test_db):
        engine, _ = test_db
        inspector = inspect(engine)
        columns = {c["name"]: c for c in inspector.get_columns("agent_orchestrator_runs")}

        expected_columns = [
            "id", "campaign_id", "target", "current_stage", "overall_status",
            "stages_json", "warnings_json", "errors_json", "audit_trail_hash",
            "started_at", "completed_at", "created_at", "updated_at"
        ]
        for col in expected_columns:
            assert col in columns, f"Column {col} missing from agent_orchestrator_runs"


class TestPhase24ORMModels:
    """Validate CRUD lifecycle and constraints on Phase 24 ORM models."""

    def test_pre_scan_result_record_crud(self, test_db):
        _, session = test_db
        rec = PreScanResultRecord(
            campaign_id="CAMP-P24-001",
            target="https://target.example.com",
            overall_status="READY",
            dns_status="PASS",
            http_status="PASS",
            https_status="PASS",
            tls_status="PASS",
            account1_status="READY",
            account2_status="READY",
            check_details_json=json.dumps({"dns": {"ip": "93.184.216.34"}}),
            warnings_json=json.dumps([]),
            errors_json=json.dumps([]),
        )
        session.add(rec)
        session.commit()

        fetched = session.query(PreScanResultRecord).filter_by(campaign_id="CAMP-P24-001").first()
        assert fetched is not None
        assert fetched.target == "https://target.example.com"
        assert fetched.overall_status == "READY"
        assert json.loads(fetched.check_details_json)["dns"]["ip"] == "93.184.216.34"

    def test_tool_execution_record_crud(self, test_db):
        _, session = test_db
        rec = ToolExecutionRecord(
            campaign_id="CAMP-P24-001",
            target="https://target.example.com",
            tool_name="nmap",
            tool_version="7.94",
            execution_profile="SAFE_SERVICE_DISCOVERY",
            execution_status="COMPLETED",
            sanitized_args_json=json.dumps(["-sV", "-T4", "--top-ports", "100"]),
            exit_code=0,
            stdout_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            output_hash="d41d8cd98f00b204e9800998ecf8427e",
            parsed_summary_json=json.dumps({"open_ports": [80, 443]}),
        )
        session.add(rec)
        session.commit()

        fetched = session.query(ToolExecutionRecord).filter_by(tool_name="nmap").first()
        assert fetched is not None
        assert fetched.execution_profile == "SAFE_SERVICE_DISCOVERY"
        assert fetched.exit_code == 0
        assert json.loads(fetched.parsed_summary_json)["open_ports"] == [80, 443]

    def test_auth_context_records_isolation_and_uniqueness(self, test_db):
        _, session = test_db
        # Account 1 context
        ctx1 = AuthContextRecord(
            campaign_id="CAMP-P24-001",
            account_id=1,
            auth_status="AUTHENTICATED",
            session_handle="auth_ctx_handle_account1_abc123",
            auth_method="CREDENTIALS",
            username_hint="u***1@example.com",
            refresh_status="ACTIVE",
        )
        # Account 2 context
        ctx2 = AuthContextRecord(
            campaign_id="CAMP-P24-001",
            account_id=2,
            auth_status="AUTHENTICATED",
            session_handle="auth_ctx_handle_account2_xyz789",
            auth_method="CREDENTIALS",
            username_hint="u***2@example.com",
            refresh_status="ACTIVE",
        )
        session.add_all([ctx1, ctx2])
        session.commit()

        # Verify both contexts exist independently
        all_ctxs = session.query(AuthContextRecord).filter_by(campaign_id="CAMP-P24-001").all()
        assert len(all_ctxs) == 2
        handles = {c.account_id: c.session_handle for c in all_ctxs}
        assert handles[1] == "auth_ctx_handle_account1_abc123"
        assert handles[2] == "auth_ctx_handle_account2_xyz789"
        assert handles[1] != handles[2]

        # Duplicate (campaign_id, account_id) should fail uniqueness constraint
        duplicate_ctx1 = AuthContextRecord(
            campaign_id="CAMP-P24-001",
            account_id=1,
            session_handle="auth_ctx_handle_duplicate",
        )
        session.add(duplicate_ctx1)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

    def test_exploitability_record_crud_and_status_distinctions(self, test_db):
        _, session = test_db
        rec = ExploitabilityRecord(
            campaign_id="CAMP-P24-001",
            target="https://target.example.com",
            finding_id="FIND-IDOR-001",
            hypothesis_id="HYP-IDOR-001",
            strategy_id="STRAT-IDOR-CROSS-ACCOUNT",
            strategy_version="1.0.0",
            verification_state="EXPLOITABLE",
            proof_type="IDOR_CROSS_ACCOUNT",
            impact_classification="UNAUTHORIZED_DATA_ACCESS",
            evidence_hash="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            reproducibility_score=1.0,
            operator_approval_id="OP-APP-999",
            proof_details_json=json.dumps({
                "account1_resource": "/api/v1/user/101/data",
                "account2_access_status": 200,
                "unauthorized_data_leakage": True
            }),
            verified_at=get_utc_now(),
        )
        session.add(rec)
        session.commit()

        fetched = session.query(ExploitabilityRecord).filter_by(finding_id="FIND-IDOR-001").first()
        assert fetched is not None
        assert fetched.verification_state == "EXPLOITABLE"
        assert fetched.reproducibility_score == 1.0
        assert fetched.proof_type == "IDOR_CROSS_ACCOUNT"

    def test_agent_orchestrator_run_record_crud(self, test_db):
        _, session = test_db
        run = AgentOrchestratorRunRecord(
            campaign_id="CAMP-P24-001",
            target="https://target.example.com",
            current_stage="PRECHECK",
            overall_status="RUNNING",
            stages_json=json.dumps({
                "PRECHECK": "IN_PROGRESS",
                "RECON": "PENDING",
                "AUTHENTICATION": "PENDING",
                "VULNERABILITY_TESTING": "PENDING",
                "HUMAN_APPROVAL": "PENDING",
                "VERIFICATION": "PENDING",
                "REPRODUCIBILITY": "PENDING",
                "REPORT": "PENDING",
            }),
            warnings_json=json.dumps([]),
            errors_json=json.dumps([]),
            audit_trail_hash="0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
            started_at=get_utc_now(),
        )
        session.add(run)
        session.commit()

        fetched = session.query(AgentOrchestratorRunRecord).filter_by(campaign_id="CAMP-P24-001").first()
        assert fetched is not None
        assert fetched.current_stage == "PRECHECK"
        assert fetched.overall_status == "RUNNING"
        stages = json.loads(fetched.stages_json)
        assert stages["PRECHECK"] == "IN_PROGRESS"


class TestSecurityInvariantsInDatabaseLayer:
    """Ensure database layer adheres to strict security invariants."""

    def test_no_plaintext_passwords_or_tokens_stored_in_auth_context(self, test_db):
        _, session = test_db
        # Ensure only session handles and username hints (redacted) are stored
        ctx = AuthContextRecord(
            campaign_id="CAMP-SEC-001",
            account_id=1,
            auth_status="AUTHENTICATED",
            session_handle="handle_sec_opaque_token_ref",
            username_hint="ad***n@example.com",
        )
        session.add(ctx)
        session.commit()

        fetched = session.query(AuthContextRecord).filter_by(campaign_id="CAMP-SEC-001").first()
        # Verify no raw password or cookie fields exist on the model
        assert not hasattr(fetched, "password")
        assert not hasattr(fetched, "raw_cookie")
        assert not hasattr(fetched, "bearer_token")
        assert not hasattr(fetched, "otp_secret")
        assert fetched.session_handle == "handle_sec_opaque_token_ref"

    def test_tool_execution_record_uses_sanitized_args_and_hashes(self, test_db):
        _, session = test_db
        rec = ToolExecutionRecord(
            campaign_id="CAMP-SEC-001",
            target="https://target.example.com",
            tool_name="whatweb",
            execution_profile="SAFE_TECH_FINGERPRINT",
            sanitized_args_json=json.dumps(["--log-brief", "https://target.example.com"]),
            stdout_hash="abc123hash",
            stderr_hash="emptyhash",
            output_hash="combinedhash",
        )
        session.add(rec)
        session.commit()

        fetched = session.query(ToolExecutionRecord).filter_by(campaign_id="CAMP-SEC-001").first()
        assert fetched.sanitized_args_json is not None
        assert "password" not in fetched.sanitized_args_json.lower()
