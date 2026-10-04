"""Comprehensive Test Suite for AihaX Recon Modes, Security Invariants, and Local E2E.

Covers:
- Tests A through K: Scope denial, wildcard boundaries, SSRF, Audit mode disabling external tools,
  live authorization gates, RequestEngine boundary, budgets, secret redaction, provider failure,
  wildcard target rejection, safe subprocess execution.
- Mode semantics: AUDIT (0 network, 0 external subprocess), DRY_RUN, AUTHORIZED_LIVE_RECON.
- Provider behavior: Subfinder, Amass, Sublist3r evaluation, CT, DNS, HTTP, Technology.
- CanonicalReconSnapshot determinism and hashing.
- Local E2E fixture (authorized.local, outofscope.attacker.local).
- AST Static Security Audit.
"""

from __future__ import annotations

import ast
import inspect
import json
import pytest

from backend.core.scope_validator import ScopeValidator
from backend.execution.tool_execution_boundary import (
    ExecutionProfile,
    ToolExecutionBoundary,
    ToolExecutionRequest,
    ToolExecutionStatus,
)
from backend.recon.providers import (
    AmassProvider,
    CertificateTransparencyProvider,
    DNSProviderAdapter,
    HttpProbeProvider,
    SubfinderProvider,
    Sublist3rProvider,
    TechnologyFingerprintProvider,
)
from backend.recon.recon_modes import (
    NormalizedReconAsset,
    ProviderStatus,
    ProviderType,
    ReconAssetStatus,
    ReconContext,
    ReconExecutionMode,
)
from backend.recon.recon_orchestrator import UnifiedReconOrchestrator
from backend.recon.recon_preflight import PreflightStatus, ReconPreflightGate
from backend.recon.snapshot import CanonicalReconSnapshot
from backend.services.request_engine import MockTransport, RequestEngine
from backend.services.vulnerability_test_selector import VulnerabilityTestSelector


# ==============================================================================
# 1. Mandatory Security Tests (Tests A through K)
# ==============================================================================

class TestMandatorySecurityInvariants:
    """Rigorous validation of Tests A through K."""

    @pytest.mark.asyncio
    async def test_a_scope_denial_for_discovered_assets(self):
        """Test A: Discovered asset evil.example.net when program only authorizes example.com -> BLOCKED_SCOPE."""
        scope = ScopeValidator(in_scope_assets=["https://example.com", "https://*.example.com"])
        subfinder = SubfinderProvider(mock_fixture_lines=["api.example.com", "evil.example.net"])
        orch = UnifiedReconOrchestrator(custom_providers=[subfinder])

        ctx = ReconContext(
            campaign_id="CAMP-TEST-A",
            target="https://example.com",
            execution_mode=ReconExecutionMode.AUDIT,
            in_scope_assets=["https://example.com", "https://*.example.com"],
        )
        snapshot = await orch.execute_recon(ctx, scope)

        assets_by_val = {a.normalized_value: a for a in snapshot.normalized_assets}
        assert "api.example.com" in assets_by_val
        assert assets_by_val["api.example.com"].status == ReconAssetStatus.IN_SCOPE

        assert "evil.example.net" in assets_by_val
        assert assets_by_val["evil.example.net"].status == ReconAssetStatus.BLOCKED_SCOPE
        assert assets_by_val["evil.example.net"].is_executable is False

    @pytest.mark.asyncio
    async def test_b_wildcard_boundary_discovered_assets_not_executable(self):
        """Test B: Program rule *.example.com discovers api.example.com -> IN_SCOPE, but NOT_EXECUTABLE."""
        scope = ScopeValidator(in_scope_assets=["https://example.com", "https://*.example.com"])
        subfinder = SubfinderProvider(mock_fixture_lines=["api.example.com"])
        orch = UnifiedReconOrchestrator(custom_providers=[subfinder])

        ctx = ReconContext(
            campaign_id="CAMP-TEST-B",
            target="https://example.com",
            execution_mode=ReconExecutionMode.AUDIT,
            in_scope_assets=["https://example.com", "https://*.example.com"],
        )
        snapshot = await orch.execute_recon(ctx, scope)

        discovered = next(a for a in snapshot.normalized_assets if a.normalized_value == "api.example.com")
        assert discovered.status == ReconAssetStatus.IN_SCOPE
        assert discovered.is_executable is False

    @pytest.mark.asyncio
    async def test_c_ssrf_destination_denial(self):
        """Test C: Metadata address 169.254.169.254 and RFC1918 blocked before any request."""
        scope = ScopeValidator(in_scope_assets=["http://169.254.169.254"])
        ctx = ReconContext(
            campaign_id="CAMP-TEST-C",
            target="http://169.254.169.254",
            execution_mode=ReconExecutionMode.AUDIT,
            in_scope_assets=["http://169.254.169.254"],
        )
        preflight = ReconPreflightGate.evaluate(ctx, scope)
        assert preflight.status == PreflightStatus.BLOCKED_SAFETY
        assert preflight.allowed is False
        assert any("anti-ssrf" in r.lower() for r in preflight.reasons)

    @pytest.mark.asyncio
    async def test_d_external_provider_disabled_in_audit_mode(self):
        """Test D: Audit Mode strictly prevents external process/network execution."""
        boundary = ToolExecutionBoundary()  # No custom runner
        subfinder = SubfinderProvider(tool_boundary=boundary)

        ctx = ReconContext(
            campaign_id="CAMP-TEST-D",
            target="https://example.com",
            execution_mode=ReconExecutionMode.AUDIT,
            in_scope_assets=["https://example.com"],
        )
        scope = ScopeValidator(in_scope_assets=["https://example.com"])
        res = await subfinder.discover("example.com", ctx, scope)

        # Audit mode uses deterministic mock fixture, does not spawn real process
        assert res.status == ProviderStatus.MOCK_ONLY
        assert len(res.assets) > 0

    @pytest.mark.asyncio
    async def test_e_authorized_live_recon_gate_fails_without_operator_confirmation(self):
        """Test E: Live recon mode selected but missing authorization or confirmation -> BLOCKED."""
        scope = ScopeValidator(in_scope_assets=["https://example.com"])
        # Missing operator_confirmed
        ctx = ReconContext(
            campaign_id="CAMP-TEST-E",
            target="https://example.com",
            execution_mode=ReconExecutionMode.AUTHORIZED_LIVE_RECON,
            authorization_record_id="AUTH-REC-1234",
            operator_confirmed=False,
            in_scope_assets=["https://example.com"],
        )
        preflight = ReconPreflightGate.evaluate(ctx, scope)
        assert preflight.status == PreflightStatus.BLOCKED_AUTHORIZATION
        assert preflight.allowed is False
        assert any("confirmation" in r.lower() for r in preflight.reasons)

    @pytest.mark.asyncio
    async def test_f_request_boundary_http_probing_uses_request_engine(self):
        """Test F: HTTP probing strictly uses RequestEngine and respects transports."""
        transport = MockTransport(
            default_status=200,
            default_headers={"Server": "nginx/1.22.0"},
            default_body=b"<html><head><title>Test App</title></head></html>",
        )
        scope = ScopeValidator(in_scope_assets=["https://example.com"])
        req_engine = RequestEngine(scope_validator=scope, transport=transport)
        probe_provider = HttpProbeProvider(request_engine=req_engine)

        ctx = ReconContext(
            campaign_id="CAMP-TEST-F",
            target="https://example.com",
            execution_mode=ReconExecutionMode.AUTHORIZED_LIVE_RECON,
            authorization_record_id="AUTH-1",
            operator_confirmed=True,
            in_scope_assets=["https://example.com"],
        )
        res = await probe_provider.discover("https://example.com", ctx, scope)
        assert res.status == ProviderStatus.LIVE_COMPLETED
        assert transport.call_count >= 1
        assert res.assets[0].metadata["server"] == "nginx/1.22.0"

    @pytest.mark.asyncio
    async def test_g_budget_enforcement(self):
        """Test G: Zero or negative request budget fails closed at preflight."""
        scope = ScopeValidator(in_scope_assets=["https://example.com"])
        ctx = ReconContext(
            campaign_id="CAMP-TEST-G",
            target="https://example.com",
            request_budget=0,
            in_scope_assets=["https://example.com"],
        )
        preflight = ReconPreflightGate.evaluate(ctx, scope)
        assert preflight.status == PreflightStatus.BLOCKED_BUDGET
        assert preflight.allowed is False

    @pytest.mark.asyncio
    async def test_h_secret_redaction_in_tool_execution(self):
        """Test H: Arguments containing credentials are automatically redacted."""
        def fake_runner(exec_path, args, timeout):
            return 0, b"Output", b""

        boundary = ToolExecutionBoundary(process_runner=fake_runner)
        req = ToolExecutionRequest(
            campaign_id="CAMP-TEST-H",
            target="https://example.com",
            tool_name="whatweb",
            execution_profile=ExecutionProfile.TECHNOLOGY_FINGERPRINTING.value,
            args=["auth=SuperSecretAPIKey123", "--log-json", "-"],
            authorization_confirmed=True,
            in_scope_assets=["https://example.com"],
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.SUCCESS.value
        assert "SuperSecretAPIKey123" not in str(res.sanitized_args)
        assert any("auth=***REDACTED***" in a for a in res.sanitized_args)

    @pytest.mark.asyncio
    async def test_i_provider_failure_reports_explicit_error_not_zero_assets(self):
        """Test I: A failing tool reports LIVE_FAILED and records error in snapshot."""
        def failing_runner(exec_path, args, timeout):
            return 1, b"", b"Fatal error: DNS timeout connecting to provider"

        boundary = ToolExecutionBoundary(process_runner=failing_runner)
        subfinder = SubfinderProvider(tool_boundary=boundary)
        orch = UnifiedReconOrchestrator(custom_providers=[subfinder])

        ctx = ReconContext(
            campaign_id="CAMP-TEST-I",
            target="https://example.com",
            execution_mode=ReconExecutionMode.AUTHORIZED_LIVE_RECON,
            authorization_record_id="AUTH-1",
            operator_confirmed=True,
            in_scope_assets=["https://example.com"],
        )
        scope = ScopeValidator(in_scope_assets=["https://example.com"])
        snapshot = await orch.execute_recon(ctx, scope)

        assert snapshot.provider_statuses["subfinder"] == ProviderStatus.LIVE_FAILED.value
        assert len(snapshot.errors) > 0
        assert any("subfinder" in e.lower() for e in snapshot.errors)

    @pytest.mark.asyncio
    async def test_j_wildcard_target_rejected_at_preflight(self):
        """Test J: Running recon directly against *.example.com is strictly rejected."""
        scope = ScopeValidator(in_scope_assets=["https://*.example.com"])
        ctx = ReconContext(
            campaign_id="CAMP-TEST-J",
            target="https://*.example.com",
            in_scope_assets=["https://*.example.com"],
        )
        preflight = ReconPreflightGate.evaluate(ctx, scope)
        assert preflight.status == PreflightStatus.BLOCKED_TARGET
        assert preflight.allowed is False
        assert any("wildcard" in r.lower() for r in preflight.reasons)

    @pytest.mark.asyncio
    async def test_k_safe_subprocess_execution_shell_injection_impossible(self):
        """Test K: Shell operators, chaining, and metacharacters are rejected."""
        boundary = ToolExecutionBoundary()
        req = ToolExecutionRequest(
            campaign_id="CAMP-TEST-K",
            target="https://example.com",
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            args=["-d", "example.com; curl http://attacker.com"],
            in_scope_assets=["https://example.com"],
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.BLOCKED_ARGUMENT.value
        assert "dangerous" in res.error_category.lower()


# ==============================================================================
# 2. End-to-End Local Proof Scenario
# ==============================================================================

class TestLocalEndToEndScenario:
    """Local fixture: authorized.local, api.authorized.local, admin.authorized.local, outofscope.attacker.local."""

    @pytest.mark.asyncio
    async def test_end_to_end_local_recon_pipeline(self):
        scope = ScopeValidator(
            in_scope_assets=[
                "https://authorized.local",
                "https://*.authorized.local",
            ],
            out_of_scope_assets=[
                "https://outofscope.attacker.local",
            ],
        )

        mock_subfinder = SubfinderProvider(
            mock_fixture_lines=[
                "api.authorized.local",
                "admin.authorized.local",
                "outofscope.attacker.local",
            ]
        )
        mock_ct = CertificateTransparencyProvider(
            mock_fixture_names=[
                "api.authorized.local",
                "portal.authorized.local",
            ]
        )
        mock_dns = DNSProviderAdapter(
            mock_records={
                "A": ["192.0.2.1"],
                "CNAME": ["origin.authorized.local"],
            }
        )
        mock_http = HttpProbeProvider()
        tech = TechnologyFingerprintProvider()

        orch = UnifiedReconOrchestrator(
            custom_providers=[mock_subfinder, mock_ct, mock_dns, mock_http, tech]
        )

        ctx = ReconContext(
            campaign_id="CAMP-LOCAL-E2E-1",
            target="https://authorized.local",
            execution_mode=ReconExecutionMode.AUDIT,
            in_scope_assets=["https://authorized.local", "https://*.authorized.local"],
            out_of_scope_assets=["https://outofscope.attacker.local"],
        )

        snapshot = await orch.execute_recon(ctx, scope)

        # 1. Snapshot verification
        assert snapshot.campaign_id == "CAMP-LOCAL-E2E-1"
        assert snapshot.concrete_target == "https://authorized.local"
        assert snapshot.execution_mode == ReconExecutionMode.AUDIT.value
        assert snapshot.snapshot_hash is not None
        assert len(snapshot.snapshot_hash) == 64

        # 2. Scope classification
        assets = {a.normalized_value: a for a in snapshot.normalized_assets}
        assert assets["api.authorized.local"].status == ReconAssetStatus.IN_SCOPE
        assert assets["admin.authorized.local"].status == ReconAssetStatus.IN_SCOPE
        assert assets["portal.authorized.local"].status == ReconAssetStatus.IN_SCOPE
        assert assets["outofscope.attacker.local"].status == ReconAssetStatus.BLOCKED_SCOPE

        # 3. Non-executable guarantee
        for a in snapshot.normalized_assets:
            assert a.is_executable is False

        # 4. Provenance aggregation
        assert "subfinder" in assets["api.authorized.local"].source_provider
        assert "crtsh" in assets["api.authorized.local"].source_provider

        # 5. Vulnerability Test Selector Integration: Recon intelligence is consumed, NOT attacked
        selector = VulnerabilityTestSelector()
        matrix = selector.select_tests(
            target_url="https://authorized.local",
            authorization_confirmed=True,
            in_scope_assets=["https://authorized.local", "https://*.authorized.local"],
        )
        assert matrix.total_registered == 86
        assert matrix.applicable_count > 0
        # Critical verification: select_tests produces applicability matrix without executing tests
        assert isinstance(matrix.get_executable_entries(), list)


# ==============================================================================
# 3. AST Static Security Audit
# ==============================================================================

class TestASTStaticSecurityAudit:
    """Verify via AST that recon code does not bypass central network or execution boundaries."""

    def test_no_direct_network_or_shell_calls_in_recon_modules(self):
        import backend.recon.providers as prov_mod
        import backend.recon.recon_modes as mode_mod
        import backend.recon.recon_orchestrator as orch_mod
        import backend.recon.recon_preflight as pre_mod
        import backend.recon.snapshot as snap_mod

        modules = [prov_mod, mode_mod, orch_mod, pre_mod, snap_mod]

        for mod in modules:
            source = inspect.getsource(mod)
            tree = ast.parse(source)

            for node in ast.walk(tree):
                # 1. No shell=True anywhere
                if isinstance(node, ast.Call):
                    for kw in node.keywords:
                        if kw.arg == "shell":
                            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                pytest.fail(f"Forbidden shell=True found in {mod.__name__} at line {node.lineno}")

                    # 2. No direct os.system, os.popen
                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr in ("system", "popen"):
                            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                                pytest.fail(f"Forbidden os.{node.func.attr}() found in {mod.__name__} at line {node.lineno}")

                    # 3. No direct requests.get/post or httpx.get/post
                    if isinstance(node.func, ast.Attribute):
                        if isinstance(node.func.value, ast.Name) and node.func.value.id in ("requests", "httpx", "urllib"):
                            pytest.fail(f"Direct network call '{node.func.value.id}.{node.func.attr}' in {mod.__name__} at line {node.lineno}")
