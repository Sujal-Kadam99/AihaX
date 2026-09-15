"""Unit tests for Phase 24 ReconAgent & Recon Pipeline."""

import ast
import asyncio
import inspect
import json
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.agents.recon_agent import (
    ReconAgent,
    ReconExecutionConfig,
    ReconObservation,
    ReconObservationCategory,
    ReconPipelineStatus,
    canonicalize_url,
    normalize_hostname,
)
from backend.execution.tool_execution_boundary import (
    ExecutionProfile,
    ToolExecutionBoundary,
    ToolExecutionRequest,
    ToolExecutionStatus,
)
from backend.models.database import Base, Scan
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


class TestReconPreconditionGating:
    """Validate target validation, wildcard rejection, scope, and destination safety."""

    @pytest.mark.asyncio
    async def test_concrete_target_accepted(self):
        called = False

        def fake_runner(exec_path, args, timeout):
            nonlocal called
            called = True
            return 0, b"sub.example.com\n", b""

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        agent = ReconAgent(tool_boundary=boundary)
        cfg = ReconExecutionConfig(
            campaign_id="CAMP-RECON-1",
            target_url="https://app.example.com",
            authorization_confirmed=True,
            in_scope_assets=["https://app.example.com"],
        )
        snapshot = await agent.execute_recon_pipeline(cfg)
        assert snapshot.status in (ReconPipelineStatus.COMPLETED.value, ReconPipelineStatus.PARTIAL_SUCCESS.value)
        assert snapshot.target == "https://app.example.com"
        assert called is True

    @pytest.mark.asyncio
    async def test_wildcard_target_rejected(self):
        called = False

        def fake_runner(exec_path, args, timeout):
            nonlocal called
            called = True
            return 0, b"", b""

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        agent = ReconAgent(tool_boundary=boundary)
        cfg = ReconExecutionConfig(
            campaign_id="CAMP-RECON-2",
            target_url="https://*.example.com",
            authorization_confirmed=True,
            in_scope_assets=["*.example.com"],
        )
        snapshot = await agent.execute_recon_pipeline(cfg)
        assert snapshot.status == ReconPipelineStatus.BLOCKED_SAFETY.value
        assert called is False
        assert any("wildcard" in e.lower() for e in snapshot.errors)

    @pytest.mark.asyncio
    async def test_multi_target_rejected(self):
        called = False

        def fake_runner(exec_path, args, timeout):
            nonlocal called
            called = True
            return 0, b"", b""

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        agent = ReconAgent(tool_boundary=boundary)
        cfg = ReconExecutionConfig(
            campaign_id="CAMP-RECON-3",
            target_url="https://app.example.com,https://api.example.com",
            authorization_confirmed=True,
        )
        snapshot = await agent.execute_recon_pipeline(cfg)
        assert snapshot.status == ReconPipelineStatus.BLOCKED_SAFETY.value
        assert called is False

    @pytest.mark.asyncio
    async def test_out_of_scope_target_rejected(self):
        called = False

        def fake_runner(exec_path, args, timeout):
            nonlocal called
            called = True
            return 0, b"", b""

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        agent = ReconAgent(tool_boundary=boundary)
        cfg = ReconExecutionConfig(
            campaign_id="CAMP-RECON-4",
            target_url="https://unauthorized.target.com",
            authorization_confirmed=True,
            in_scope_assets=["https://app.example.com"],
        )
        snapshot = await agent.execute_recon_pipeline(cfg)
        assert snapshot.status == ReconPipelineStatus.BLOCKED_SCOPE.value
        assert called is False

    @pytest.mark.asyncio
    async def test_explicit_exclusion_rejected(self):
        called = False

        def fake_runner(exec_path, args, timeout):
            nonlocal called
            called = True
            return 0, b"", b""

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        agent = ReconAgent(tool_boundary=boundary)
        cfg = ReconExecutionConfig(
            campaign_id="CAMP-RECON-5",
            target_url="https://admin.example.com",
            authorization_confirmed=True,
            in_scope_assets=["*.example.com"],
            out_of_scope_assets=["admin.example.com"],
        )
        snapshot = await agent.execute_recon_pipeline(cfg)
        assert snapshot.status == ReconPipelineStatus.BLOCKED_SCOPE.value
        assert called is False

    @pytest.mark.asyncio
    async def test_private_ip_ssrf_destination_rejected(self):
        called = False

        def fake_runner(exec_path, args, timeout):
            nonlocal called
            called = True
            return 0, b"", b""

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        agent = ReconAgent(tool_boundary=boundary)
        cfg = ReconExecutionConfig(
            campaign_id="CAMP-RECON-6",
            target_url="https://10.0.0.1",
            authorization_confirmed=True,
            in_scope_assets=["https://10.0.0.1"],
        )
        snapshot = await agent.execute_recon_pipeline(cfg)
        assert snapshot.status == ReconPipelineStatus.BLOCKED_SAFETY.value
        assert called is False


class TestReconPassiveVsActiveAndProvenance:
    """Validate passive execution without active authorization and provenance preservation."""

    @pytest.mark.asyncio
    async def test_missing_authorization_disables_active_tools(self):
        active_tool_called = False
        passive_tool_called = False

        def fake_runner(exec_path, args, timeout):
            nonlocal active_tool_called, passive_tool_called
            if "nmap" in exec_path or "gobuster" in exec_path:
                active_tool_called = True
            if "subfinder" in exec_path or "gau" in exec_path:
                passive_tool_called = True
            return 0, b"sub.example.com\n", b""

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        agent = ReconAgent(tool_boundary=boundary)
        cfg = ReconExecutionConfig(
            campaign_id="CAMP-AUTH-1",
            target_url="https://app.example.com",
            authorization_confirmed=False,  # Unconfirmed authorization
            in_scope_assets=["https://app.example.com"],
        )
        snapshot = await agent.execute_recon_pipeline(cfg)
        # Hardened boundary: external tools (subfinder) require authorization and fail closed
        assert passive_tool_called is False
        assert active_tool_called is False
        assert snapshot.tool_results["subfinder"]["execution_status"] == ToolExecutionStatus.BLOCKED_AUTHORIZATION.value
        assert any("active reconnaissance tools" in w for w in snapshot.warnings)

    @pytest.mark.asyncio
    async def test_duplicate_observations_merged_and_provenance_preserved(self):
        # Simulate Subfinder and Amass finding the same subdomain
        def fake_runner(exec_path, args, timeout):
            if "subfinder" in exec_path:
                return 0, b"api.example.com\nportal.example.com\n", b""
            if "amass" in exec_path:
                return 0, b"api.example.com\nadmin.example.com\n", b""
            return 0, b"", b""

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        agent = ReconAgent(tool_boundary=boundary)
        cfg = ReconExecutionConfig(
            campaign_id="CAMP-DEDUP-1",
            target_url="https://example.com",
            authorization_confirmed=True,
            in_scope_assets=["https://example.com"],
            enable_port_scan=False,
            enable_tech_detection=False,
            enable_url_discovery=False,
            enable_directory_discovery=False,
        )
        snapshot = await agent.execute_recon_pipeline(cfg)
        api_obs = next((o for o in snapshot.observations if o.normalized_value == "api.example.com"), None)
        assert api_obs is not None
        assert "subfinder" in api_obs.discovered_by
        assert "amass" in api_obs.discovered_by
        assert len(api_obs.discovered_by) == 2


class TestNormalizationAndHashing:
    """Validate canonicalization of URLs, hostnames, tech stacks, and snapshot determinism."""

    def test_canonicalize_url(self):
        assert canonicalize_url("HTTP://EXAMPLE.COM:80/path/test?q=1#frag") == "http://example.com/path/test?q=1"
        assert canonicalize_url("https://example.com:443/") == "https://example.com/"
        assert canonicalize_url("example.com/login") == "https://example.com/login"

    def test_normalize_hostname(self):
        assert normalize_hostname("API.EXAMPLE.COM.") == "api.example.com"
        assert normalize_hostname("user:pass@host.com:8080") == "host.com"

    @pytest.mark.asyncio
    async def test_repeated_identical_input_produces_identical_snapshot_hash(self):
        def fake_runner(exec_path, args, timeout):
            if "subfinder" in exec_path:
                return 0, b"sub1.example.com\nsub2.example.com\n", b""
            if "gau" in exec_path:
                return 0, b"https://example.com/api/v1?id=1\nhttps://example.com/login\n", b""
            return 0, b"", b""

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        agent = ReconAgent(tool_boundary=boundary)
        cfg = ReconExecutionConfig(
            campaign_id="CAMP-HASH-1",
            target_url="https://example.com",
            authorization_confirmed=True,
            in_scope_assets=["https://example.com"],
        )
        s1 = await agent.execute_recon_pipeline(cfg)
        s2 = await agent.execute_recon_pipeline(cfg)
        assert s1.snapshot_hash == s2.snapshot_hash
        assert len(s1.snapshot_hash) == 64
        assert s1.observation_count == s2.observation_count


class TestAttackSurfaceGraphIntegration:
    """Validate AttackSurfaceGraphEngine integration."""

    @pytest.mark.asyncio
    async def test_attack_surface_graph_populated(self):
        def fake_runner(exec_path, args, timeout):
            if "gau" in exec_path:
                return 0, b"https://example.com/profile?user_id=123\nhttps://example.com/api/v1/search?q=test\n", b""
            return 0, b"", b""

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        agent = ReconAgent(tool_boundary=boundary)
        cfg = ReconExecutionConfig(
            campaign_id="CAMP-GRAPH-1",
            target_url="https://example.com",
            authorization_confirmed=True,
            in_scope_assets=["https://example.com"],
            enable_subdomain_discovery=False,
            enable_port_scan=False,
            enable_tech_detection=False,
            enable_directory_discovery=False,
        )
        snapshot = await agent.execute_recon_pipeline(cfg)
        assert snapshot.graph_snapshot is not None
        assert snapshot.graph_snapshot["node_count"] >= 3  # target, endpoints, parameters
        assert snapshot.graph_snapshot["edge_count"] >= 2  # links and parameter relations
        assert "snapshot_hash" in snapshot.graph_snapshot


class TestLegacyBaseAgentCompatibility:
    """Validate backwards compatibility with BaseAgent execute() and Scan DB model."""

    @pytest.mark.asyncio
    async def test_legacy_execute_runs_and_updates_scan(self, test_db):
        def fake_runner(exec_path, args, timeout):
            return 0, b"sub.example.com\n", b""

        # Create scan record in database
        scan = Scan(
            id="SCAN-COMPAT-1",
            target_url="https://app.example.com",
            status="pending",
        )
        test_db.add(scan)
        test_db.commit()

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        agent = ReconAgent(
            scan_id="SCAN-COMPAT-1",
            db=test_db,
            config={"target_url": "https://app.example.com", "authorization_confirmed": True},
            tool_boundary=boundary,
        )
        result = await agent.execute()
        assert isinstance(result, dict)
        assert "subdomains" in result
        assert "snapshot_hash" in result


class TestReconParsersAndToolIntegrations:
    """Validate tool output parsers and error handling."""

    @pytest.mark.asyncio
    async def test_whatweb_json_parsing(self):
        whatweb_json = json.dumps([
            {
                "target": "https://example.com",
                "http_status": 200,
                "plugins": {
                    "HTTPServer": {"string": ["nginx/1.24.0"], "version": "1.24.0"},
                    "React": {"version": "18.2.0"},
                    "Strict-Transport-Security": {"string": ["max-age=31536000"]},
                },
            }
        ])

        def fake_runner(exec_path, args, timeout):
            if "whatweb" in exec_path:
                return 0, whatweb_json.encode("utf-8"), b""
            return 0, b"", b""

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        agent = ReconAgent(tool_boundary=boundary)
        cfg = ReconExecutionConfig(
            campaign_id="CAMP-WHATWEB-1",
            target_url="https://example.com",
            authorization_confirmed=True,
            in_scope_assets=["https://example.com"],
            enable_subdomain_discovery=False,
            enable_port_scan=False,
            enable_url_discovery=False,
            enable_directory_discovery=False,
        )
        snapshot = await agent.execute_recon_pipeline(cfg)
        tech_obs = [o for o in snapshot.observations if o.category == ReconObservationCategory.TECHNOLOGY.value]
        tech_names = [o.normalized_value for o in tech_obs]
        assert "react" in tech_names
        assert "httpserver" in tech_names

    @pytest.mark.asyncio
    async def test_nmap_output_parsing(self):
        nmap_output = (
            "PORT     STATE SERVICE VERSION\n"
            "80/tcp   open  http    nginx 1.24.0\n"
            "443/tcp  open  ssl/http\n"
            "8080/tcp open  http-proxy\n"
        )

        def fake_runner(exec_path, args, timeout):
            if "nmap" in exec_path:
                return 0, nmap_output.encode("utf-8"), b""
            return 0, b"", b""

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        agent = ReconAgent(tool_boundary=boundary)
        cfg = ReconExecutionConfig(
            campaign_id="CAMP-NMAP-1",
            target_url="https://example.com",
            authorization_confirmed=True,
            in_scope_assets=["https://example.com"],
            enable_subdomain_discovery=False,
            enable_tech_detection=False,
            enable_url_discovery=False,
            enable_directory_discovery=False,
        )
        snapshot = await agent.execute_recon_pipeline(cfg)
        port_obs = [o for o in snapshot.observations if o.category == ReconObservationCategory.PORT.value]
        assert len(port_obs) == 3
        assert any(o.metadata.get("port") == 80 for o in port_obs)
        assert any(o.metadata.get("port") == 443 for o in port_obs)

    @pytest.mark.asyncio
    async def test_gobuster_directory_parsing(self):
        gobuster_output = (
            "/admin (Status: 301) [Size: 178]\n"
            "/api (Status: 200) [Size: 450]\n"
            "/login (Status: 200) [Size: 1200]\n"
        )

        def fake_runner(exec_path, args, timeout):
            if "gobuster" in exec_path:
                return 0, gobuster_output.encode("utf-8"), b""
            return 0, b"", b""

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        agent = ReconAgent(tool_boundary=boundary)
        cfg = ReconExecutionConfig(
            campaign_id="CAMP-GOBUSTER-1",
            target_url="https://example.com",
            authorization_confirmed=True,
            in_scope_assets=["https://example.com"],
            enable_subdomain_discovery=False,
            enable_port_scan=False,
            enable_tech_detection=False,
            enable_url_discovery=False,
        )
        snapshot = await agent.execute_recon_pipeline(cfg)
        dir_obs = [o for o in snapshot.observations if o.category == ReconObservationCategory.DIRECTORY.value]
        assert len(dir_obs) == 3

    @pytest.mark.asyncio
    async def test_dns_and_tls_analysis(self):
        def fake_dns(domain):
            return {
                "A": ["93.184.216.34"],
                "MX": ["mail.example.com"],
                "TXT": ["v=spf1 include:_spf.example.com ~all"],
            }

        def fake_tls(domain, port):
            return {
                "issuer": "DigiCert Inc",
                "valid_until": "2027-05-01",
                "sans": ["example.com", "www.example.com"],
            }

        boundary = ToolExecutionBoundary(process_runner=lambda e, a, t: (0, b"", b""))
        agent = ReconAgent(tool_boundary=boundary, dns_resolver=fake_dns, tls_inspector=fake_tls)
        cfg = ReconExecutionConfig(
            campaign_id="CAMP-DNS-TLS-1",
            target_url="https://example.com",
            authorization_confirmed=True,
            in_scope_assets=["https://example.com"],
            enable_subdomain_discovery=False,
            enable_port_scan=False,
            enable_tech_detection=False,
            enable_url_discovery=False,
            enable_directory_discovery=False,
        )
        snapshot = await agent.execute_recon_pipeline(cfg)
        dns_obs = [o for o in snapshot.observations if o.category == ReconObservationCategory.DNS_RECORD.value]
        tls_obs = [o for o in snapshot.observations if o.category == ReconObservationCategory.CERTIFICATE.value]
        assert len(dns_obs) == 3
        assert len(tls_obs) == 1
        assert "digicert" in tls_obs[0].normalized_value

    @pytest.mark.asyncio
    async def test_partial_tool_failure_handled(self):
        def fake_runner(exec_path, args, timeout):
            if "subfinder" in exec_path:
                return 0, b"sub.example.com\n", b""
            if "amass" in exec_path:
                return 1, b"", b"Error connecting to data source"
            return 0, b"", b""

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        agent = ReconAgent(tool_boundary=boundary)
        cfg = ReconExecutionConfig(
            campaign_id="CAMP-PARTIAL-1",
            target_url="https://example.com",
            authorization_confirmed=True,
            in_scope_assets=["https://example.com"],
            enable_port_scan=False,
            enable_tech_detection=False,
            enable_url_discovery=False,
            enable_directory_discovery=False,
        )
        snapshot = await agent.execute_recon_pipeline(cfg)
        assert snapshot.status == ReconPipelineStatus.PARTIAL_SUCCESS.value
        assert snapshot.tool_results["subfinder"]["execution_status"] == ToolExecutionStatus.SUCCESS.value
        assert snapshot.tool_results["amass"]["execution_status"] == ToolExecutionStatus.PROCESS_ERROR.value


class TestStaticSecurityInvariants:
    """Ensure ReconAgent source code never calls subprocess, os.system, or shell=True directly."""

    def test_no_direct_subprocess_or_forbidden_constructs(self):
        import backend.agents.recon_agent as module

        source = inspect.getsource(module)
        tree = ast.parse(source)

        for node in ast.walk(tree):
            # 1. Check for shell=True in any function call kwargs
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "shell":
                        if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            pytest.fail(f"Forbidden shell=True found at line {node.lineno}")

                # 2. Check for subprocess, os.system, os.popen calls
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("system", "popen"):
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                            pytest.fail(f"Forbidden os.{node.func.attr}() found at line {node.lineno}")
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                        pytest.fail(f"Direct subprocess call '{node.func.attr}' found at line {node.lineno}")

                # 3. Check for eval() or exec() calls
                if isinstance(node.func, ast.Name):
                    if node.func.id in ("eval", "exec"):
                        pytest.fail(f"Forbidden {node.func.id}() call found at line {node.lineno}")

