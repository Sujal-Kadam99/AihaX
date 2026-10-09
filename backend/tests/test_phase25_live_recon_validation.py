"""AihaX Phase 25 — Tool-by-Tool Live Recon Validation Gate Test Suite.

Verifies:
1. Unit Tests:
   - Tool command construction
   - Argument safety & injection blocking
   - Output parsing for all tools
   - Output normalization & provenance tagging
   - Authorization gate enforcement (BLOCKED_AUTHORIZATION)
   - Scope gate enforcement (BLOCKED_SCOPE)
   - Destination safety (BLOCKED_SAFETY)
   - Timeout and size limits
   - Strict classification enum (all 13 statuses)
   - Sublist3r formally classified as NOT_IMPLEMENTED
   - Nuclei & Dalfox classified as NOT_SELECTED_RECON_ONLY
   - Nmap & Gobuster classified as BLOCKED_POLICY unless authorized

2. Integration Tests:
   - ToolExecutionBoundary -> Adapter -> Parser -> Normalizer -> ReconSnapshot -> AttackSurfaceGraph
   - Cross-tool correlation and deduplication preserving provenance
   - AttackSurfaceGraph node and edge proof

3. Live Validation:
   - Concrete target https://www.mitacsc.ac.in (host: www.mitacsc.ac.in, domain: mitacsc.ac.in)
   - Zero false success: Uninstalled binaries report EXECUTION_FAILED
   - Truthful failure reporting
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import pytest
from unittest import mock
from unittest.mock import AsyncMock, MagicMock, patch

from backend.core.scope_validator import ScopeValidator
from backend.execution.tool_execution_boundary import (
    ExecutionProfile,
    ToolExecutionBoundary,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from backend.recon.live_recon_validator import (
    LiveReconValidationEngine,
    Phase25ValidationSuiteResult,
    ReconLifecycleEvent,
    ToolExecutionRecord,
    ToolValidationStatus,
    select_service_scan_ports,
    compress_nmap_port_list,
)
from backend.recon.recon_modes import ReconAssetStatus, ReconExecutionMode
from backend.recon.snapshot import CanonicalReconSnapshot
from backend.services.request_engine import MockTransport, RequestEngine


# ==============================================================================
# SECTION 1: UNIT TESTS
# ==============================================================================

class TestPhase25UnitGates:
    """Unit tests for tool command construction, safety gates, and parsing."""

    def test_strict_classification_enum_coverage(self):
        """Verify all 13 authoritative classification statuses are present."""
        expected_statuses = {
            "NOT_IMPLEMENTED",
            "NOT_SELECTED",
            "NOT_SELECTED_RECON_ONLY",
            "BLOCKED_AUTHORIZATION",
            "BLOCKED_SCOPE",
            "BLOCKED_POLICY",
            "BLOCKED_SAFETY",
            "BLOCKED_BUDGET",
            "EXECUTION_FAILED",
            "EXECUTED_ZERO_RESULTS",
            "EXECUTED_RESULTS_CAPTURED",
            "EXECUTED_RESULTS_NORMALIZED",
            "EXECUTED_RESULTS_INTEGRATED",
            "LIVE_VALIDATED",
        }
        actual_statuses = {s.value for s in ToolValidationStatus}
        assert expected_statuses.issubset(actual_statuses)

    def test_service_scan_ports_follow_authorized_scope_and_exclusions(self):
        assert select_service_scan_ports(
            allowed_ports=[80, 443, 8443, 9443],
            excluded_ports=[443],
            profile="web_common",
        ) == [80, 8443]
        assert select_service_scan_ports(
            allowed_ports=[80, 443, 8443, 9443],
            excluded_ports=[443],
            profile="all_authorized",
        ) == [80, 8443, 9443]

    def test_service_scan_requires_an_explicit_authorized_port_list(self):
        assert select_service_scan_ports([], [], profile="all_authorized") == []

    def test_nmap_port_spec_compresses_ranges_without_changing_coverage(self):
        assert compress_nmap_port_list([1, 2, 3, 80, 443, 444, 445]) == "1-3,80,443-445"

    @pytest.mark.asyncio
    async def test_nmap_request_uses_only_authorized_non_excluded_ports_and_scope_rules(self):
        from types import SimpleNamespace

        captured = {}

        class CapturingBoundary:
            async def execute(self, request):
                captured["request"] = request
                return SimpleNamespace(
                    execution_status=ToolExecutionStatus.SUCCESS.value,
                    duration_ms=1,
                    exit_code=0,
                    stdout="8443/tcp open https-alt",
                    stdout_hash="stdout-hash",
                    stderr_hash="stderr-hash",
                    output_hash="evidence-hash",
                    error_category=None,
                    stderr="",
                )

        engine = LiveReconValidationEngine(tool_boundary=CapturingBoundary())
        engine.tool_availability.resolve_binary_path = lambda _tool: "nmap.exe"
        scope_validator = ScopeValidator(
            in_scope_assets=["example.test", "*.example.test"],
            out_of_scope_assets=["private.example.test"],
        )

        record = await engine._validate_nmap(
            base_domain="app.example.test",
            target="https://app.example.test",
            campaign_id="campaign",
            auth_id="authorization",
            allow_port_scan=True,
            scope_validator=scope_validator,
            scope_hash="scope-hash",
            allowed_ports=[80, 443, 8443, 9443],
            excluded_ports=[443, 9443],
            service_scan_profile="all_authorized",
        )

        request = captured["request"]
        assert record.status == ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED
        assert request.args == ["-sT", "-T2", "-p", "80,8443", "--open", "app.example.test"]
        assert request.allowed_ports == [80, 8443]
        assert request.excluded_ports == [443, 9443]
        assert request.in_scope_assets == ["example.test", "*.example.test"]
        assert request.out_of_scope_assets == ["private.example.test"]

    def test_sublist3r_formally_not_implemented(self):
        """Sublist3r must be explicitly marked NOT_IMPLEMENTED with documented rationale."""
        engine = LiveReconValidationEngine()
        rec = engine._validate_sublist3r(
            target="https://www.mitacsc.ac.in",
            campaign_id="test-camp",
            auth_id="auth-123",
            scope_hash="hash-123",
        )
        assert rec.tool_name == "sublist3r"
        assert rec.status in (ToolValidationStatus.NOT_IMPLEMENTED, ToolValidationStatus.STUB_ONLY)
        assert "not part of the current AihaX recon implementation" in rec.failure_reason
        assert any("SUBLIST3R_NOT_IMPLEMENTED" in ev for ev in rec.lifecycle_events)

    def test_nuclei_and_dalfox_classified_not_selected_recon_only(self):
        """Vulnerability scanners must default to NOT_SELECTED_RECON_ONLY in recon gate."""
        engine = LiveReconValidationEngine()
        rec_nuclei = engine._validate_nuclei(
            target="https://www.mitacsc.ac.in",
            campaign_id="test-camp",
            auth_id="auth-123",
            scope_hash="hash-123",
        )
        assert rec_nuclei.tool_name == "nuclei"
        assert rec_nuclei.status == ToolValidationStatus.NOT_SELECTED_RECON_ONLY
        assert "vulnerability scanner" in rec_nuclei.failure_reason.lower()

        rec_dalfox = engine._validate_dalfox(
            target="https://www.mitacsc.ac.in",
            campaign_id="test-camp",
            auth_id="auth-123",
            scope_hash="hash-123",
        )
        assert rec_dalfox.tool_name == "dalfox"
        assert rec_dalfox.status == ToolValidationStatus.NOT_SELECTED_RECON_ONLY
        assert "xss scanner" in rec_dalfox.failure_reason.lower()

    @pytest.mark.asyncio
    async def test_nmap_and_gobuster_blocked_without_policy_permission(self):
        """Nmap and Gobuster must be BLOCKED_POLICY unless explicitly authorized."""
        engine = LiveReconValidationEngine()
        scope_validator = ScopeValidator(in_scope_assets=["https://www.mitacsc.ac.in"])

        rec_nmap = await engine._validate_nmap(
            base_domain="mitacsc.ac.in",
            target="https://www.mitacsc.ac.in",
            campaign_id="test-camp",
            auth_id="auth-123",
            allow_port_scan=False,  # Unauthorized
            scope_validator=scope_validator,
            scope_hash="hash-123",
        )
        assert rec_nmap.status == ToolValidationStatus.BLOCKED_POLICY
        assert "Port scanning is not explicitly authorized" in rec_nmap.failure_reason

        rec_gobuster = await engine._validate_gobuster(
            target="https://www.mitacsc.ac.in",
            campaign_id="test-camp",
            auth_id="auth-123",
            allow_dir_scan=False,  # Unauthorized
            scope_validator=scope_validator,
            scope_hash="hash-123",
        )
        assert rec_gobuster.status == ToolValidationStatus.BLOCKED_POLICY
        assert "Directory brute-forcing" in rec_gobuster.failure_reason

    @pytest.mark.asyncio
    async def test_authorization_gate_fails_closed_when_missing(self):
        """Missing authorization record or operator confirmation halts execution with BLOCKED_AUTHORIZATION."""
        engine = LiveReconValidationEngine()

        # Case A: authorization_record_id is None
        res_no_auth = await engine.execute_validation_suite(
            target="https://www.mitacsc.ac.in",
            campaign_id="camp-unauth",
            authorization_record_id=None,
            operator_confirmed=False,
        )
        assert res_no_auth.suite_status == ToolValidationStatus.BLOCKED_AUTHORIZATION.value
        assert res_no_auth.live_validated_count == 0
        assert res_no_auth.executed_tools_count == 0
        assert all(r.status == ToolValidationStatus.BLOCKED_AUTHORIZATION for r in res_no_auth.tool_records.values())

        # Case B: operator_confirmed is False
        res_no_conf = await engine.execute_validation_suite(
            target="https://www.mitacsc.ac.in",
            campaign_id="camp-unauth",
            authorization_record_id="auth-rec-valid",
            operator_confirmed=False,
        )
        assert res_no_conf.suite_status == ToolValidationStatus.BLOCKED_AUTHORIZATION.value

    @pytest.mark.asyncio
    async def test_scope_gate_blocks_out_of_scope_target(self):
        """Targets not in scope_assets must be rejected with BLOCKED_SCOPE."""
        engine = LiveReconValidationEngine()
        res_out_of_scope = await engine.execute_validation_suite(
            target="https://unauthorized-evil.com",
            campaign_id="camp-scope",
            authorization_record_id="auth-123",
            operator_confirmed=True,
            scope_assets=["https://www.mitacsc.ac.in"],
        )
        assert res_out_of_scope.suite_status == ToolValidationStatus.BLOCKED_SCOPE.value
        assert all(r.status == ToolValidationStatus.BLOCKED_SCOPE for r in res_out_of_scope.tool_records.values())

    @pytest.mark.asyncio
    async def test_destination_safety_blocks_ssrf(self):
        """Private RFC1918 / localhost / cloud metadata targets must be rejected with BLOCKED_SAFETY."""
        engine = LiveReconValidationEngine()
        res_ssrf = await engine.execute_validation_suite(
            target="http://169.254.169.254/latest/meta-data",
            campaign_id="camp-ssrf",
            authorization_record_id="auth-123",
            operator_confirmed=True,
            scope_assets=["http://169.254.169.254/latest/meta-data"],
        )
        assert res_ssrf.suite_status == ToolValidationStatus.BLOCKED_SAFETY.value

    @pytest.mark.asyncio
    async def test_tool_execution_boundary_rejects_dangerous_args(self):
        """ToolExecutionBoundary must block shell injection characters in arguments."""
        boundary = ToolExecutionBoundary()
        req = ToolExecutionRequest(
            campaign_id="camp-1",
            target="https://www.mitacsc.ac.in",
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            args=["-d", "mitacsc.ac.in; rm -rf /", "-silent"],
            authorization_confirmed=True,
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.BLOCKED_ARGUMENT.value
        assert "dangerous" in res.error_category.lower() or "blocked" in res.error_category.lower()

    def test_tool_execution_record_fields_compliance(self):
        """Verify ToolExecutionRecord contains all required Section 4 audit fields."""
        rec = ToolExecutionRecord(
            tool_name="subfinder",
            tool_version="v2.6.3",
            campaign_id="camp-123",
            authorization_record_id="auth-456",
            target="https://www.mitacsc.ac.in",
            scope_snapshot_hash="scope-hash-abc",
            arguments=["-d", "mitacsc.ac.in", "-silent"],
            exit_code=0,
            stdout_hash="stdout-sha",
            stderr_hash="stderr-sha",
            raw_output_size=128,
            parsed_result_count=3,
            normalized_result_count=3,
            snapshot_contribution_count=3,
            evidence_id="ev-789",
            status=ToolValidationStatus.LIVE_VALIDATED,
        )
        d = rec.to_dict()
        required_fields = [
            "tool_name", "tool_version", "execution_id", "campaign_id",
            "authorization_record_id", "target", "scope_snapshot_hash",
            "execution_mode", "started_at", "completed_at", "duration_ms",
            "arguments", "exit_code", "stdout_hash", "stderr_hash",
            "raw_output_size", "parsed_result_count", "normalized_result_count",
            "snapshot_contribution_count", "evidence_id", "status", "failure_reason",
        ]
        for f in required_fields:
            assert f in d, f"Missing required Section 4 field: {f}"
        assert d["status"] == "LIVE_VALIDATED"


# ==============================================================================
# SECTION 2: INTEGRATION & PIPELINE TESTS (Mocked Boundary)
# ==============================================================================

class TestPhase25IntegrationPipeline:
    """Integration test proving the full ToolExecutionBoundary -> Parser -> Normalizer -> ReconSnapshot pipeline."""

    @pytest.mark.asyncio
    async def test_subfinder_pipeline_to_reconsnapshot_and_graph(self):
        """Prove Subfinder output reaches Parser, Normalization, ReconSnapshot, and AttackSurfaceGraph."""
        mock_boundary = MagicMock(spec=ToolExecutionBoundary)
        mock_stdout = "portal.mitacsc.ac.in\nalumni.mitacsc.ac.in\nexam.mitacsc.ac.in\n"
        mock_stdout_hash = hashlib.sha256(mock_stdout.encode("utf-8")).hexdigest()

        mock_boundary.execute = AsyncMock(return_value=ToolExecutionResult(
            id="exec-sub-1",
            campaign_id="camp-pipe",
            target="https://www.mitacsc.ac.in",
            tool_name="subfinder",
            tool_version="v2.6.3",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            execution_status=ToolExecutionStatus.SUCCESS.value,
            sanitized_args=["-d", "mitacsc.ac.in", "-silent"],
            exit_code=0,
            timeout_seconds=60,
            stdout_hash=mock_stdout_hash,
            stderr_hash=None,
            output_hash=mock_stdout_hash,
            stdout=mock_stdout,
            stderr=None,
            duration_ms=450.0,
        ))

        # Patch shutil.which to simulate installed binary
        with patch("shutil.which", return_value="/usr/local/bin/subfinder"):
            engine = LiveReconValidationEngine(tool_boundary=mock_boundary)
            scope_validator = ScopeValidator(in_scope_assets=["https://www.mitacsc.ac.in", "https://*.mitacsc.ac.in"])

            rec = await engine._validate_subfinder(
                base_domain="mitacsc.ac.in",
                target="https://www.mitacsc.ac.in",
                campaign_id="camp-pipe",
                auth_id="auth-pipe",
                scope_validator=scope_validator,
                scope_hash="hash-pipe",
            )

        # 1. Output Captured
        assert rec.exit_code == 0
        assert rec.stdout_hash == mock_stdout_hash
        assert rec.parsed_result_count == 3

        # 2. Output Normalized with Provenance
        assert rec.normalized_result_count == 3
        for item in rec.normalized_assets:
            assert item["source"] == "subfinder"
            assert item["source_execution_id"] == rec.execution_id
            assert item["type"] == "subdomain"
            assert item["authorization_status"] == "DISCOVERED_NOT_AUTHORIZED"
            assert "mitacsc.ac.in" in item["asset"]

        # 3. Lifecycle events recorded
        assert any(ReconLifecycleEvent.RECON_TOOL_OUTPUT_CAPTURED.value in ev for ev in rec.lifecycle_events)
        assert any(ReconLifecycleEvent.RECON_TOOL_RESULTS_NORMALIZED.value in ev for ev in rec.lifecycle_events)

    @pytest.mark.asyncio
    async def test_cross_tool_correlation_and_deduplication(self):
        """Multiple tools observing the same domain must be deduplicated while preserving provenance."""
        engine = LiveReconValidationEngine()

        # Simulate outputs from Subfinder and CT discovering the same subdomain
        rec_subfinder = ToolExecutionRecord(
            tool_name="subfinder",
            execution_id="exec-1",
            status=ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED,
            normalized_assets=[
                {"asset": "portal.mitacsc.ac.in", "type": "subdomain", "source": "subfinder", "authorization_status": "DISCOVERED_NOT_AUTHORIZED"},
                {"asset": "unique-sub.mitacsc.ac.in", "type": "subdomain", "source": "subfinder", "authorization_status": "DISCOVERED_NOT_AUTHORIZED"},
            ],
            stdout_hash="hash-1",
            evidence_id="ev-1",
        )
        rec_ct = ToolExecutionRecord(
            tool_name="crtsh",
            execution_id="exec-2",
            status=ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED,
            normalized_assets=[
                {"asset": "portal.mitacsc.ac.in", "type": "subdomain", "source": "crtsh", "authorization_status": "DISCOVERED_NOT_AUTHORIZED"},
                {"asset": "unique-ct.mitacsc.ac.in", "type": "subdomain", "source": "crtsh", "authorization_status": "DISCOVERED_NOT_AUTHORIZED"},
            ],
            stdout_hash="hash-2",
            evidence_id="ev-2",
        )

        all_assets = []
        evidence_hashes = []
        prov_map = {}

        engine._ingest_tool_assets(rec_subfinder, all_assets, evidence_hashes, prov_map)
        engine._ingest_tool_assets(rec_ct, all_assets, evidence_hashes, prov_map)

        assert len(all_assets) == 4
        deduped = engine._deduplicate_assets(all_assets, prov_map)

        # 3 unique assets expected: portal (shared), unique-sub, unique-ct
        assert len(deduped) == 3

        # Check provenance for shared asset
        portal_asset = next(a for a in deduped if a.normalized_value == "portal.mitacsc.ac.in")
        sources = portal_asset.metadata.get("provenance_sources", [])
        assert "subfinder" in sources
        assert "crtsh" in sources

        # Check non-executable rule preserved
        assert all(a.is_executable is False for a in deduped)


# ==============================================================================
# SECTION 3: LIVE RECON VALIDATION SUITE (Real Target Execution Gate)
# ==============================================================================

class TestPhase25LiveReconValidationGate:
    """Live target validation against https://www.mitacsc.ac.in."""

    @pytest.mark.asyncio
    async def test_live_recon_blocked_when_target_not_authorized_in_database(self):
        """Section 1 Safety Rule: Without a valid authorization record, STOP LIVE EXECUTION."""
        engine = LiveReconValidationEngine()

        # Running without authorization record
        result = await engine.execute_validation_suite(
            target="https://www.mitacsc.ac.in",
            campaign_id="unauthorized-camp-test",
            authorization_record_id=None,
            operator_confirmed=False,
        )

        assert result.suite_status == ToolValidationStatus.BLOCKED_AUTHORIZATION.value
        assert result.live_validated_count == 0
        assert result.executed_tools_count == 0
        assert result.safety_audit_passed is True

        for tool_name, rec in result.tool_records.items():
            assert rec.status == ToolValidationStatus.BLOCKED_AUTHORIZATION
            assert "STOP LIVE EXECUTION" in rec.failure_reason

    @pytest.mark.asyncio
    @mock.patch("backend.recon.recon_tool_availability.ReconToolAvailability.resolve_binary_path", return_value=None)
    async def test_live_recon_validation_suite_with_explicit_authorization(self, mock_resolve):
        """When explicitly authorized, executes permitted native tools and truthfully reports binary availability."""
        
        engine = LiveReconValidationEngine()
        target = "https://www.mitacsc.ac.in"
        campaign_id = "phase25-mitacsc-auth-camp"
        auth_record_id = "auth-mitacsc-phase25-record-valid"

        result: Phase25ValidationSuiteResult = await engine.execute_validation_suite(
            target=target,
            campaign_id=campaign_id,
            authorization_record_id=auth_record_id,
            operator_confirmed=True,
            scope_assets=["https://www.mitacsc.ac.in"],
            allow_port_scan=False,  # Enforce port scanning policy: disabled by default
            allow_dir_scan=False,   # Enforce brute-force policy: disabled by default
        )

        assert result.suite_status == "VALIDATION_COMPLETE"
        assert result.target == target
        assert result.host == "www.mitacsc.ac.in"
        assert result.base_domain == "mitacsc.ac.in"
        assert result.total_tools_evaluated == 13

        # 1. DNS Reconnaissance (Native dnspython execution against real target)
        rec_dns = result.tool_records["dns_recon"]
        assert rec_dns.exit_code == 0
        assert rec_dns.status in (ToolValidationStatus.LIVE_VALIDATED, ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED)
        assert rec_dns.raw_output is not None
        assert rec_dns.parsed_result_count > 0
        assert rec_dns.stdout_hash is not None

        # 2. HTTP/HTTPS Probing (Native RequestEngine + HttpProbeEngine execution)
        rec_http = result.tool_records["http_probe"]
        assert rec_http.exit_code == 0
        assert rec_http.status in (ToolValidationStatus.LIVE_VALIDATED, ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED)
        assert rec_http.normalized_result_count >= 1
        assert rec_http.stdout_hash is not None

        # 3. Sublist3r MUST be STUB_ONLY or NOT_IMPLEMENTED
        rec_sublist3r = result.tool_records["sublist3r"]
        assert rec_sublist3r.status in (ToolValidationStatus.NOT_IMPLEMENTED, ToolValidationStatus.STUB_ONLY)

        # 4. Nuclei and Dalfox MUST be NOT_SELECTED_RECON_ONLY
        assert result.tool_records["nuclei"].status == ToolValidationStatus.NOT_SELECTED_RECON_ONLY
        assert result.tool_records["dalfox"].status == ToolValidationStatus.NOT_SELECTED_RECON_ONLY

        # 5. Nmap and Gobuster MUST be BLOCKED_POLICY (policy forbids active port/dir fuzzing)
        assert result.tool_records["nmap"].status == ToolValidationStatus.BLOCKED_POLICY
        assert result.tool_records["gobuster"].status == ToolValidationStatus.BLOCKED_POLICY

        # 6. Uninstalled CLI tools MUST report BINARY_UNAVAILABLE (or EXECUTION_FAILED)
        for tool_name in ["subfinder", "amass", "gau", "whatweb"]:
            rec = result.tool_records[tool_name]
            assert rec.status in (ToolValidationStatus.EXECUTION_FAILED, ToolValidationStatus.BINARY_UNAVAILABLE)
            assert "not found on system PATH" in rec.failure_reason

        # 7. ReconSnapshot & AttackSurfaceGraph Integration Proof
        assert result.recon_snapshot is not None
        assert result.recon_snapshot.snapshot_hash is not None
        assert len(result.recon_snapshot.normalized_assets) > 0

        # Non-negotiable invariant: Discovered assets are tagged DISCOVERED_NOT_AUTHORIZED / not executable
        for a in result.recon_snapshot.normalized_assets:
            if a.normalized_value != "www.mitacsc.ac.in":
                assert a.is_executable is False
                assert a.metadata.get("authorization_status") in ("DISCOVERED_NOT_AUTHORIZED", None)
