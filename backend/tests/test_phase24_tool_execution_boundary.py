"""Unit tests for Phase 24 ToolExecutionBoundary."""

import asyncio
import inspect
import json
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.execution.tool_execution_boundary import (
    ALLOWED_TOOLS,
    CapabilityClass,
    ExecutionProfile,
    ToolDefinition,
    ToolExecutionBoundary,
    ToolExecutionRequest,
    ToolExecutionStatus,
)
from backend.models.database import Base, ToolExecutionRecord
from backend.models.migrations import run_migrations


@pytest.fixture
def test_db():
    """Create a fresh in-memory SQLite database."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    run_migrations(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


class TestToolAllowlistAndProfiles:
    """Validate tool allowlist and execution profiles."""

    @pytest.mark.asyncio
    async def test_unknown_tool_rejected(self):
        boundary = ToolExecutionBoundary()
        req = ToolExecutionRequest(
            campaign_id="CAMP-TOOL-1",
            target="https://app.example.com",
            tool_name="malicious_tool",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.BLOCKED_TOOL.value
        assert "not permitted in allowlist" in res.error_category

    @pytest.mark.asyncio
    async def test_unknown_or_mismatched_profile_rejected(self):
        boundary = ToolExecutionBoundary()
        # subfinder cannot run XSS_VALIDATION profile
        req = ToolExecutionRequest(
            campaign_id="CAMP-TOOL-2",
            target="https://app.example.com",
            tool_name="subfinder",
            execution_profile=ExecutionProfile.XSS_VALIDATION.value,
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.BLOCKED_PROFILE.value


class TestTargetSafetyAndScopeGating:
    """Validate concrete target, wildcard rejection, scope, and destination safety."""

    @pytest.mark.asyncio
    async def test_wildcard_target_rejected(self):
        boundary = ToolExecutionBoundary()
        req = ToolExecutionRequest(
            campaign_id="CAMP-SAFE-1",
            target="https://*.example.com",
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.BLOCKED_SAFETY.value
        assert "wildcard" in res.error_category.lower()

    @pytest.mark.asyncio
    async def test_empty_target_rejected(self):
        boundary = ToolExecutionBoundary()
        req = ToolExecutionRequest(
            campaign_id="CAMP-SAFE-2",
            target="",
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.BLOCKED_SAFETY.value

    @pytest.mark.asyncio
    async def test_out_of_scope_target_rejected(self):
        boundary = ToolExecutionBoundary()
        req = ToolExecutionRequest(
            campaign_id="CAMP-SCOPE-1",
            target="https://unauthorized.target.com",
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            in_scope_assets=["https://app.example.com"],
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.BLOCKED_SCOPE.value

    @pytest.mark.asyncio
    async def test_explicit_exclusion_target_rejected(self):
        boundary = ToolExecutionBoundary()
        req = ToolExecutionRequest(
            campaign_id="CAMP-SCOPE-2",
            target="https://admin.example.com",
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            in_scope_assets=["*.example.com"],
            out_of_scope_assets=["admin.example.com"],
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.BLOCKED_SCOPE.value

    @pytest.mark.asyncio
    async def test_private_ip_destination_rejected(self):
        boundary = ToolExecutionBoundary()
        req = ToolExecutionRequest(
            campaign_id="CAMP-SSRF-1",
            target="https://10.0.0.1",
            tool_name="nmap",
            execution_profile=ExecutionProfile.PORT_SERVICE_DISCOVERY.value,
            authorization_confirmed=True,
            in_scope_assets=["https://10.0.0.1"],
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.BLOCKED_SAFETY.value

    @pytest.mark.asyncio
    async def test_loopback_destination_rejected(self):
        boundary = ToolExecutionBoundary()
        req = ToolExecutionRequest(
            campaign_id="CAMP-SSRF-2",
            target="https://127.0.0.1",
            tool_name="nmap",
            execution_profile=ExecutionProfile.PORT_SERVICE_DISCOVERY.value,
            authorization_confirmed=True,
            in_scope_assets=["https://127.0.0.1"],
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.BLOCKED_SAFETY.value

    @pytest.mark.asyncio
    async def test_metadata_ip_rejected(self):
        boundary = ToolExecutionBoundary()
        req = ToolExecutionRequest(
            campaign_id="CAMP-SSRF-3",
            target="https://169.254.169.254",
            tool_name="nmap",
            execution_profile=ExecutionProfile.PORT_SERVICE_DISCOVERY.value,
            authorization_confirmed=True,
            in_scope_assets=["https://169.254.169.254"],
        )
        res = await boundary.execute(req)
        assert res.execution_status in (ToolExecutionStatus.BLOCKED_SAFETY.value, ToolExecutionStatus.BLOCKED_SCOPE.value)


class TestAuthorizationGating:
    """Validate active vs passive authorization policies."""

    @pytest.mark.asyncio
    async def test_active_tool_unauthorized_rejected(self):
        # nmap is an active tool -> requires explicit authorization
        boundary = ToolExecutionBoundary()
        req = ToolExecutionRequest(
            campaign_id="CAMP-AUTH-1",
            target="https://app.example.com",
            tool_name="nmap",
            execution_profile=ExecutionProfile.PORT_SERVICE_DISCOVERY.value,
            authorization_confirmed=False,  # Unauthorized
            in_scope_assets=["https://app.example.com"],
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.BLOCKED_AUTHORIZATION.value

    @pytest.mark.asyncio
    async def test_passive_tool_permits_execution_with_scope(self):
        # Subfinder requires authorization in hardened boundary
        runner_called = False

        def fake_runner(exec_path, args, timeout):
            nonlocal runner_called
            runner_called = True
            return 0, b'{"host":"app.example.com"}\n', b""

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        # 1. Blocked without authorization
        req_unauth = ToolExecutionRequest(
            campaign_id="CAMP-PASSIVE-1",
            target="https://app.example.com",
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            authorization_confirmed=False,
            in_scope_assets=["https://app.example.com"],
        )
        res_unauth = await boundary.execute(req_unauth)
        assert res_unauth.execution_status == ToolExecutionStatus.BLOCKED_AUTHORIZATION.value
        assert runner_called is False

        # 2. Allowed with explicit authorization
        req_auth = ToolExecutionRequest(
            campaign_id="CAMP-PASSIVE-1",
            target="https://app.example.com",
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            authorization_confirmed=True,
            in_scope_assets=["https://app.example.com"],
        )
        res_auth = await boundary.execute(req_auth)
        assert res_auth.execution_status == ToolExecutionStatus.SUCCESS.value
        assert runner_called is True


class TestArgumentValidationAndInjectionPrevention:
    """Validate argument sanitization and shell injection denial."""

    @pytest.mark.asyncio
    async def test_semicolon_command_chaining_rejected(self):
        boundary = ToolExecutionBoundary()
        req = ToolExecutionRequest(
            campaign_id="CAMP-INJ-1",
            target="https://app.example.com",
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            args=["-d", "example.com; rm -rf /"],
            in_scope_assets=["https://app.example.com"],
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.BLOCKED_ARGUMENT.value

    @pytest.mark.asyncio
    async def test_pipe_and_redirection_rejected(self):
        boundary = ToolExecutionBoundary()
        req = ToolExecutionRequest(
            campaign_id="CAMP-INJ-2",
            target="https://app.example.com",
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            args=["-d", "example.com | cat /etc/passwd"],
            in_scope_assets=["https://app.example.com"],
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.BLOCKED_ARGUMENT.value

    @pytest.mark.asyncio
    async def test_backtick_command_substitution_rejected(self):
        boundary = ToolExecutionBoundary()
        req = ToolExecutionRequest(
            campaign_id="CAMP-INJ-3",
            target="https://app.example.com",
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            args=["-d", "`whoami`.example.com"],
            in_scope_assets=["https://app.example.com"],
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.BLOCKED_ARGUMENT.value

    @pytest.mark.asyncio
    async def test_sensitive_credential_argument_redacted(self):
        def fake_runner(exec_path, args, timeout):
            return 0, b"OK", b""

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        req = ToolExecutionRequest(
            campaign_id="CAMP-REDACT-1",
            target="https://app.example.com",
            tool_name="whatweb",
            execution_profile=ExecutionProfile.TECHNOLOGY_FINGERPRINTING.value,
            args=["--user-agent", "AihaX", "auth=SuperSecret123"],
            authorization_confirmed=True,
            in_scope_assets=["https://app.example.com"],
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.SUCCESS.value
        assert "SuperSecret123" not in str(res.sanitized_args)
        assert any("auth=***REDACTED***" in a for a in res.sanitized_args)


class TestExecutionResultsAndEvidenceHashing:
    """Validate deterministic execution results, hashes, timeouts, and limits."""

    @pytest.mark.asyncio
    async def test_successful_fake_execution_and_hashes(self):
        stdout_data = b"subdomain1.example.com\nsubdomain2.example.com\n"
        stderr_data = b"[INF] Finished in 2s\n"

        def fake_runner(exec_path, args, timeout):
            return 0, stdout_data, stderr_data

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        req = ToolExecutionRequest(
            campaign_id="CAMP-HASH-1",
            target="https://app.example.com",
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            authorization_confirmed=True,
            in_scope_assets=["https://app.example.com"],
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.SUCCESS.value
        assert res.exit_code == 0
        assert res.stdout_hash is not None
        assert res.stderr_hash is not None
        assert res.output_hash is not None
        assert len(res.stdout_hash) == 64
        assert res.stdout == stdout_data.decode("utf-8")

    @pytest.mark.asyncio
    async def test_process_error_exit_code_mapped(self):
        def fake_runner(exec_path, args, timeout):
            return 1, b"", b"Fatal error: target host unreachable"

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        req = ToolExecutionRequest(
            campaign_id="CAMP-ERR-1",
            target="https://app.example.com",
            tool_name="nmap",
            execution_profile=ExecutionProfile.PORT_SERVICE_DISCOVERY.value,
            authorization_confirmed=True,
            in_scope_assets=["https://app.example.com"],
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.PROCESS_ERROR.value
        assert res.exit_code == 1

    @pytest.mark.asyncio
    async def test_timeout_enforced(self):
        def fake_timeout_runner(exec_path, args, timeout):
            raise asyncio.TimeoutError()

        boundary = ToolExecutionBoundary(process_runner=fake_timeout_runner)
        req = ToolExecutionRequest(
            campaign_id="CAMP-TIMEOUT-1",
            target="https://app.example.com",
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            timeout_seconds=5,
            authorization_confirmed=True,
            in_scope_assets=["https://app.example.com"],
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.TIMEOUT.value
        assert "timed out" in res.error_category.lower()

    @pytest.mark.asyncio
    async def test_not_installed_executable(self):
        # Custom boundary with non-existent executable and no custom runner
        tools = {
            "subfinder": ToolDefinition(
                name="subfinder",
                executable="non_existent_binary_xyz_12345",
                allowed_profiles={ExecutionProfile.SUBDOMAIN_ENUMERATION.value},
                capability_class=CapabilityClass.PASSIVE_RECON.value,
                is_active=False,
                requires_authorization=False,
            )
        }
        boundary = ToolExecutionBoundary(tool_registry=tools)
        req = ToolExecutionRequest(
            campaign_id="CAMP-MISSING-1",
            target="https://app.example.com",
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            in_scope_assets=["https://app.example.com"],
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.NOT_INSTALLED.value


class TestDatabasePersistenceIntegration:
    """Validate ToolExecutionRecord persistence in database."""

    @pytest.mark.asyncio
    async def test_tool_execution_record_persisted(self, test_db):
        def fake_runner(exec_path, args, timeout):
            return 0, b"Discovered: test.example.com", b""

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        req = ToolExecutionRequest(
            campaign_id="CAMP-DB-TOOL-1",
            target="https://app.example.com",
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            args=["-d", "example.com", "auth=SecretKey"],
            authorization_confirmed=True,
            in_scope_assets=["https://app.example.com"],
        )
        res = await boundary.execute(req, db=test_db)
        assert res.execution_status == ToolExecutionStatus.SUCCESS.value

        # Query database to verify record
        rec = test_db.query(ToolExecutionRecord).filter_by(campaign_id="CAMP-DB-TOOL-1").first()
        assert rec is not None
        assert rec.tool_name == "subfinder"
        assert rec.execution_profile == ExecutionProfile.SUBDOMAIN_ENUMERATION.value
        assert rec.execution_status == ToolExecutionStatus.SUCCESS.value
        assert rec.exit_code == 0
        assert rec.output_hash is not None
        # Verify secret was not persisted
        assert "SecretKey" not in rec.sanitized_args_json


class TestBoundaryExtendedScenarios:
    """Validate prohibited ports, stream limits, and registry definitions."""

    @pytest.mark.asyncio
    async def test_prohibited_port_rejected(self):
        boundary = ToolExecutionBoundary()
        req = ToolExecutionRequest(
            campaign_id="CAMP-PORT-1",
            target="https://app.example.com:22",  # SSH port 22 is prohibited for HTTP/recon
            tool_name="nmap",
            execution_profile=ExecutionProfile.PORT_SERVICE_DISCOVERY.value,
            authorization_confirmed=True,
            in_scope_assets=["https://app.example.com:22"],
        )
        res = await boundary.execute(req)
        assert res.execution_status in (ToolExecutionStatus.BLOCKED_SAFETY.value, ToolExecutionStatus.BLOCKED_SCOPE.value)
        assert any(k in res.error_category.lower() for k in ("prohibited", "port", "scope"))

    @pytest.mark.asyncio
    async def test_stream_reading_and_truncation_limits(self):
        boundary = ToolExecutionBoundary()
        # Test StreamReader with bounded size
        reader = asyncio.StreamReader()
        reader.feed_data(b"A" * 500)
        reader.feed_eof()
        data, truncated = await boundary._read_stream(reader, max_bytes=100)
        assert len(data) == 100
        assert truncated is True

    @pytest.mark.asyncio
    async def test_all_registry_tools_have_valid_definitions(self):
        boundary = ToolExecutionBoundary()
        assert len(boundary.registry) >= 8
        for name, tool_def in boundary.registry.items():
            assert tool_def.name == name
            assert len(tool_def.executable) > 0
            assert len(tool_def.allowed_profiles) > 0
            assert tool_def.default_timeout > 0
            assert tool_def.max_timeout >= tool_def.default_timeout
            # Allow up to 300 seconds for heavy recon tools like amass
            assert tool_def.default_timeout <= 240
            assert tool_def.max_timeout <= 300


class TestStaticSecurityChecks:
    """Ensure no forbidden constructs (shell=True, os.system, os.popen, eval, exec) exist in implementation."""

    def test_no_forbidden_constructs_in_boundary_code(self):
        import ast
        import backend.execution.tool_execution_boundary as module

        source = inspect.getsource(module)
        tree = ast.parse(source)

        for node in ast.walk(tree):
            # 1. Check for shell=True in any function call kwargs
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "shell":
                        if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            pytest.fail(f"Forbidden shell=True found at line {node.lineno}")

                # 2. Check for os.system or os.popen calls
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("system", "popen"):
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                            pytest.fail(f"Forbidden os.{node.func.attr}() found at line {node.lineno}")

                # 3. Check for eval() or exec() calls
                if isinstance(node.func, ast.Name):
                    if node.func.id in ("eval", "exec"):
                        pytest.fail(f"Forbidden {node.func.id}() call found at line {node.lineno}")
