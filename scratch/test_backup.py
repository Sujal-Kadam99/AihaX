"""AihaX Phase 26 — Comprehensive Recon Tool Installation & Functional Validation Gate Tests.

Validates:
1. Installation & availability diagnostics (binary present vs missing, version extraction, malformed output).
2. Authorization and scope gate enforcement (missing, expired, mismatch vs valid).
3. ToolExecutionBoundary invariants (structured arguments, shell injection rejection, timeouts, bounds).
4. Subfinder functional pipeline (parsing, normalization, deduplication, ReconSnapshot/AttackSurfaceGraph).
5. Amass passive/low-impact mode enforcement (passive accepted, active/intrusive flags rejected).
6. GAU historical URL parsing, canonicalization, deduplication, and out-of-scope tagging (DISCOVERED_OUT_OF_SCOPE).
7. WhatWeb read-only technology fingerprinting, JSON parsing, and evidence persistence.
8. Sublist3r formal classification as STUB_ONLY / PRODUCTION_CAPABILITY_NOT_IMPLEMENTED.
9. Nmap & Gobuster policy gating (BLOCKED_POLICY).
10. Nuclei & Dalfox reconnaissance exclusion (NOT_SELECTED_RECON_ONLY).
11. Controlled live validation gate for target https://www.mitacsc.ac.in under strict authorization.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock, patch

import pytest
from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.core.scope_validator import ScopeValidator
from backend.execution.tool_execution_boundary import (
    ALLOWED_TOOLS,
    ExecutionProfile,
    ToolExecutionBoundary,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from backend.models.database import Base, get_utc_now
from backend.persistence.models import AuthorizationRecord, Campaign
from backend.recon.live_recon_validator import (
    LiveReconValidationEngine,
    Phase25ValidationSuiteResult,
    ReconLifecycleEvent,
    ToolExecutionRecord,
    ToolValidationStatus,
)
from backend.recon.recon_modes import ReconAssetStatus, ReconExecutionMode
from backend.recon.recon_tool_availability import (
    ReconToolAvailability,
    ReconToolAvailabilityStatus,
    ToolDiagnosticResult,
    ToolInventoryRecord,
)


# ==============================================================================
# In-Memory DB Fixture for Authorization Testing
# ==============================================================================

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    camp = Campaign(
        id="camp-p26-mitacsc",
        name="Phase 26 Validation Campaign",
        target_url="https://www.mitacsc.ac.in",
        status="ACTIVE",
    )
    session.add(camp)

    now = get_utc_now()
    active_auth = AuthorizationRecord(
        id="auth-p26-valid",
        campaign_id="camp-p26-mitacsc",
        authorized_by="security-lead@aihax.local",
        scope_hash="scope-hash-p26",
        status="ACTIVE",
        expires_at=(now + timedelta(days=30)).isoformat(),
    )
    session.add(active_auth)

    expired_auth = AuthorizationRecord(
        id="auth-p26-expired",
        campaign_id="camp-p26-mitacsc",
        authorized_by="security-lead@aihax.local",
        scope_hash="scope-hash-p26-expired",
        status="ACTIVE",
        expires_at=(now - timedelta(days=1)).isoformat(),
    )
    session.add(expired_auth)

    session.commit()
    yield session
    session.close()


# ==============================================================================
# 1. Installation & Availability Diagnostics Tests (Section 6, 7, 8)
# ==============================================================================

class TestPhase26InstallationAvailability:
    """Deterministic environment diagnostics, version extraction, and inventory tests."""

    @pytest.mark.asyncio
    async def test_binary_missing_returns_binary_unavailable(self):
        """When binary is absent, diagnostics must report BINARY_UNAVAILABLE (no fake success)."""
        diag = ReconToolAvailability()
        res = await diag.diagnose_tool("subfinder")
        # In current environment, subfinder CLI is not installed
        assert res.installed is False
        assert res.status == ReconToolAvailabilityStatus.BINARY_UNAVAILABLE.value
        assert res.execution_supported is False
        assert "not found on system PATH" in (res.failure_reason or "")

    @pytest.mark.asyncio
    async def test_binary_present_and_version_detected(self):
        """When binary exists, version is deterministically extracted via structured execution."""
        def mock_runner(cmd: str, args: List[str], timeout: int) -> Tuple[int, bytes, bytes]:
            if "-version" in args:
                return 0, b"subfinder v2.6.6\n", b""
            return 0, b"", b""

        boundary = ToolExecutionBoundary(process_runner=mock_runner)
        diag = ReconToolAvailability(tool_boundary=boundary, custom_process_runner=mock_runner)

        # Mock binary resolution to simulate installed binary
        with patch.object(diag, "resolve_binary_path", return_value="/usr/bin/subfinder"):
            res = await diag.diagnose_tool("subfinder")
            assert res.installed is True
            assert res.version == "2.6.6"
            assert res.status == ReconToolAvailabilityStatus.AVAILABLE.value
            assert res.execution_supported is True
            assert res.version_stdout_hash is not None

    @pytest.mark.asyncio
    async def test_malformed_version_output_handled_gracefully(self):
        """Malformed version string does not crash and handles None version cleanly."""
        def mock_runner(cmd: str, args: List[str], timeout: int) -> Tuple[int, bytes, bytes]:
            return 0, b"unexpected garbage output with no semver\n", b""

        boundary = ToolExecutionBoundary(process_runner=mock_runner)
        diag = ReconToolAvailability(tool_boundary=boundary, custom_process_runner=mock_runner)

        with patch.object(diag, "resolve_binary_path", return_value="/usr/bin/gau"):
            res = await diag.diagnose_tool("gau")
            assert res.installed is True
            assert res.version is None
            assert res.status == ReconToolAvailabilityStatus.AVAILABLE.value

    @pytest.mark.asyncio
    async def test_tool_inventory_generation_compliance(self):
        """ToolInventoryRecord conforms to all fields in Section 6."""
        diag = ReconToolAvailability()
        inventory = await diag.generate_inventory()
        assert len(inventory) >= 9
        tool_names = {rec.tool_name for rec in inventory}
        assert {"subfinder", "amass", "gau", "whatweb", "sublist3r", "nmap", "gobuster", "nuclei", "dalfox"}.issubset(tool_names)
        for rec in inventory:
            d = rec.to_dict()
            assert "tool_name" in d
            assert "required_version" in d
            assert "installation_status" in d
            assert "availability_status" in d
            assert "adapter_status" in d
            assert "timestamp" in d


# ==============================================================================
# 2. Authorization & Scope Gate Tests (Section 1.1, 11)
# ==============================================================================

class TestPhase26AuthorizationGate:
    """Authorization and scope invariants remain fail-closed."""

    def test_no_authorization_blocks_execution(self, db_session):
        ok, auth_id, msg = LiveReconValidationEngine.verify_authorization(
            target="https://unauthorized-domain.com",
            campaign_id="camp-p26-mitacsc",
            db_session=db_session,
        )
        assert ok is False
        assert auth_id is None
        assert "No active authorization record" in msg

    def test_expired_authorization_blocks_execution(self, db_session):
        ok, auth_id, msg = LiveReconValidationEngine.verify_authorization(
            target="https://www.mitacsc.ac.in",
            campaign_id="camp-expired-camp",
            db_session=db_session,
        )
        assert ok is False
        assert auth_id is None

    def test_valid_authorization_passes_preflight(self, db_session):
        ok, auth_id, msg = LiveReconValidationEngine.verify_authorization(
            target="https://www.mitacsc.ac.in",
            campaign_id="camp-p26-mitacsc",
            db_session=db_session,
        )
        assert ok is True
        assert auth_id == "auth-p26-valid"

    def test_scope_mismatch_blocks_target(self):
        scope_validator = ScopeValidator(in_scope_assets=["www.mitacsc.ac.in"])
        decision = scope_validator.validate_target("https://attacker.com")
        assert decision.allowed is False


# ==============================================================================
# 3. Tool Boundary & Safety Invariants (Section 1.2, 10)
# ==============================================================================

class TestPhase26ToolBoundary:
    """ToolExecutionBoundary structured arguments, timeout, and anti-injection."""

    @pytest.mark.asyncio
    async def test_shell_injection_metacharacters_rejected(self):
        """Shell operators (;, &&, |, ``, $()) must be strictly rejected."""
        boundary = ToolExecutionBoundary()
        dangerous_payloads = [
            ["-d", "mitacsc.ac.in; id"],
            ["-d", "mitacsc.ac.in && cat /etc/passwd"],
            ["-d", "mitacsc.ac.in | whoami"],
            ["-d", "mitacsc.ac.in`calc.exe`"],
            ["-d", "mitacsc.ac.in$(whoami)"],
        ]
        for args in dangerous_payloads:
            req = ToolExecutionRequest(
                campaign_id="p26-camp",
                target="https://www.mitacsc.ac.in",
                tool_name="subfinder",
                execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
                args=args,
                authorization_confirmed=True,
            )
            res = await boundary.execute(req)
            assert res.execution_status == ToolExecutionStatus.BLOCKED_ARGUMENT.value
            assert "Dangerous shell metacharacter" in (res.error_category or "")

    @pytest.mark.asyncio
    async def test_timeout_enforced(self):
        """Process execution exceeding timeout must return TIMEOUT status."""
        def mock_timeout_runner(cmd: str, args: List[str], timeout: int):
            raise asyncio.TimeoutError("Execution exceeded timeout")

        boundary = ToolExecutionBoundary(process_runner=mock_timeout_runner)
        req = ToolExecutionRequest(
            campaign_id="p26-camp",
            target="https://www.mitacsc.ac.in",
            tool_name="subfinder",
            execution_profile=ExecutionProfile.SUBDOMAIN_ENUMERATION.value,
            args=["-d", "mitacsc.ac.in", "-silent"],
            timeout_seconds=5,
            authorization_confirmed=True,
            execution_mode="AUTHORIZED_LIVE_RECON",
        )
        res = await boundary.execute(req)
        assert res.execution_status == ToolExecutionStatus.TIMEOUT.value


# ==============================================================================
# 4. Subfinder Validation (Section 2.1, 13)
# ==============================================================================

class TestPhase26Subfinder:
    """Subfinder passive subdomain discovery pipeline."""

    @pytest.mark.asyncio
    async def test_subfinder_pipeline_parser_normalization_evidence(self):
        """Subfinder stdout is parsed, normalized, deduplicated, and integrated."""
        def mock_subfinder_runner(cmd: str, args: List[str], timeout: int) -> Tuple[int, bytes, bytes]:
            stdout = b"www.mitacsc.ac.in\nalumni.mitacsc.ac.in\nlibrary.mitacsc.ac.in\n"
            return 0, stdout, b""

        boundary = ToolExecutionBoundary(process_runner=mock_subfinder_runner)
        engine = LiveReconValidationEngine(tool_boundary=boundary)

        # Mock binary check to pass
        with patch.object(engine.tool_availability, "resolve_binary_path", return_value="/bin/subfinder"):
            rec = await engine._validate_subfinder(
                base_domain="mitacsc.ac.in",
                target="https://www.mitacsc.ac.in",
                campaign_id="p26-camp",
                auth_id="auth-valid",
                scope_validator=ScopeValidator(in_scope_assets=["mitacsc.ac.in", "*.mitacsc.ac.in"]),
                scope_hash="scope-hash-1",
            )

            assert rec.status == ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED
            assert rec.parsed_result_count == 3
            assert rec.normalized_result_count == 3
            assert rec.stdout_hash is not None
            assert rec.exit_code == 0
            # Ensure discovered assets are marked DISCOVERED_NOT_AUTHORIZED and not executable
            for a in rec.normalized_assets:
                assert a["authorization_status"] == "DISCOVERED_NOT_AUTHORIZED"
                assert a["is_executable"] is False

    @patch("backend.recon.recon_tool_availability.ReconToolAvailability.resolve_binary_path", return_value=None)
    @pytest.mark.asyncio
    async def test_subfinder_missing_binary_returns_binary_unavailable(self):
        """When subfinder executable is missing, return BINARY_UNAVAILABLE."""
        engine = LiveReconValidationEngine()
        with patch.object(engine.tool_availability, 'resolve_binary_path', return_value=None):
            rec = await engine._validate_subfinder(
                base_domain="mitacsc.ac.in",
                target="https://www.mitacsc.ac.in",
                campaign_id="p26-camp",
                auth_id="auth-valid",
                scope_validator=ScopeValidator(in_scope_assets=["mitacsc.ac.in"]),
                scope_hash="scope-hash-1",
            )
            assert rec.status == ToolValidationStatus.BINARY_UNAVAILABLE
            assert "not found on system PATH" in rec.failure_reason


# ==============================================================================
# 5. Amass Passive Mode Enforcement (Section 3, 14)
# ==============================================================================

class TestPhase26Amass:
    """Amass passive/low-impact mode only. Active/intrusive flags strictly rejected."""

    @pytest.mark.asyncio
    async def test_amass_passive_mode_accepted(self):
        """Passive invocation ('enum -passive -d <domain>') is accepted."""
        def mock_amass_runner(cmd: str, args: List[str], timeout: int) -> Tuple[int, bytes, bytes]:
            return 0, b"portal.mitacsc.ac.in\nexam.mitacsc.ac.in\n", b""

        boundary = ToolExecutionBoundary(process_runner=mock_amass_runner)
        engine = LiveReconValidationEngine(tool_boundary=boundary)

        with patch.object(engine.tool_availability, "resolve_binary_path", return_value="/bin/amass"):
            rec = await engine._validate_amass(
                base_domain="mitacsc.ac.in",
                target="https://www.mitacsc.ac.in",
                campaign_id="p26-camp",
                auth_id="auth-valid",
                scope_validator=ScopeValidator(in_scope_assets=["mitacsc.ac.in"]),
                scope_hash="scope-hash-1",
            )
            assert rec.status == ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED
            assert rec.parsed_result_count == 2
            assert rec.normalized_result_count == 2

    @pytest.mark.asyncio
    async def test_amass_active_mode_and_unsafe_flags_rejected(self):
        """Active flags (-active, -brute, -ip, etc.) are blocked at the adapter boundary."""
        engine = LiveReconValidationEngine()
        unsafe_argument_sets = [
            ["enum", "-active", "-d", "mitacsc.ac.in"],
            ["enum", "-passive", "-brute", "-d", "mitacsc.ac.in"],
            ["enum", "-passive", "-ip", "-d", "mitacsc.ac.in"],
            ["enum", "-passive", "-dir", "/tmp", "-d", "mitacsc.ac.in"],
        ]
        for bad_args in unsafe_argument_sets:
            rec = await engine._validate_amass(
                base_domain="mitacsc.ac.in",
                target="https://www.mitacsc.ac.in",
                campaign_id="p26-camp",
                auth_id="auth-valid",
                scope_validator=ScopeValidator(in_scope_assets=["mitacsc.ac.in"]),
                scope_hash="scope-hash-1",
                custom_args=bad_args,
            )
            assert rec.status == ToolValidationStatus.BLOCKED_POLICY
            assert "Unsafe Amass argument rejected" in rec.failure_reason

    @patch("backend.recon.recon_tool_availability.ReconToolAvailability.resolve_binary_path", return_value=None)
    @pytest.mark.asyncio
    async def test_amass_missing_binary_returns_binary_unavailable(self):
        engine = LiveReconValidationEngine()
        with patch.object(engine.tool_availability, 'resolve_binary_path', return_value=None):
            rec = await engine._validate_amass(
                base_domain="mitacsc.ac.in",
                target="https://www.mitacsc.ac.in",
                campaign_id="p26-camp",
                auth_id="auth-valid",
                scope_validator=ScopeValidator(in_scope_assets=["mitacsc.ac.in"]),
                scope_hash="scope-hash-1",
            )
            assert rec.status == ToolValidationStatus.BINARY_UNAVAILABLE


# ==============================================================================
# 6. GAU Historical URL Discovery (Section 4, 15)
# ==============================================================================


class TestPhase26GAU:
    """GAU URL discovery, canonicalization, deduplication, and scope classification."""

    @pytest.mark.asyncio
    async def test_gau_url_parsing_and_scope_classification(self):
        """URLs in-scope marked DISCOVERED_NOT_AUTHORIZED; out-of-scope marked DISCOVERED_OUT_OF_SCOPE."""
        def mock_gau_runner(cmd, args, timeout):
            stdout = (
                b"https://www.mitacsc.ac.in/about\n"
                b"https://www.mitacsc.ac.in/courses?id=1\n"
                b"https://external-thirdparty.com/ad\n"
            )
            return 0, stdout, b""

        boundary = ToolExecutionBoundary(process_runner=mock_gau_runner)
        engine = LiveReconValidationEngine(tool_boundary=boundary)

        with patch.object(engine.tool_availability, "resolve_binary_path", return_value="/bin/gau"):
            scope_val = ScopeValidator(in_scope_assets=["www.mitacsc.ac.in", "mitacsc.ac.in"])
            rec = await engine._validate_gau(
                base_domain="mitacsc.ac.in",
                target="https://www.mitacsc.ac.in",
                campaign_id="p26-camp",
                auth_id="auth-valid",
                scope_validator=scope_val,
                scope_hash="scope-hash-1",
            )
            assert rec.status == ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED
            assert rec.parsed_result_count == 3
            assert rec.normalized_result_count == 3

            in_scope_assets = [a for a in rec.normalized_assets if a["scope_status"] == "IN_SCOPE"]
            out_of_scope_assets = [a for a in rec.normalized_assets if a["scope_status"] == "OUT_OF_SCOPE"]

            assert len(in_scope_assets) == 2
            assert len(out_of_scope_assets) == 1

            for a in in_scope_assets:
                assert a["authorization_status"] == "DISCOVERED_NOT_AUTHORIZED"
                assert a["is_executable"] is False

            for a in out_of_scope_assets:
                assert a["authorization_status"] == "DISCOVERED_OUT_OF_SCOPE"
                assert a["is_executable"] is False

    @patch("backend.recon.recon_tool_availability.ReconToolAvailability.resolve_binary_path", return_value=None)
    @pytest.mark.asyncio
    async def test_gau_missing_binary_returns_binary_unavailable(self, mock_resolve):
        engine = LiveReconValidationEngine()
        rec = await engine._validate_gau(
            base_domain="mitacsc.ac.in",
            target="https://www.mitacsc.ac.in",
            campaign_id="p26-camp",
            auth_id="auth-valid",
            scope_validator=ScopeValidator(in_scope_assets=["mitacsc.ac.in"]),
            scope_hash="scope-hash-1",
        )
        assert rec.status == ToolValidationStatus.BINARY_UNAVAILABLE


# ==============================================================================
# 7. WhatWeb Fingerprinting (Section 5, 16)
# ==============================================================================

class TestPhase26WhatWeb:
    """WhatWeb read-only technology fingerprinting."""

    @pytest.mark.asyncio
    async def test_whatweb_technology_json_parsing(self):
        """JSON output is parsed and normalized into technology assets."""
        def mock_whatweb_runner(cmd, args, timeout):
            import json
            payload = [{
                "target": "https://www.mitacsc.ac.in",
                "http_status": 200,
                "plugins": {
                    "Apache": {"version": ["2.4.41"]},
                    "PHP": {"version": ["7.4.3"]},
                    "HTML5": {},
                }
            }]
            return 0, json.dumps(payload).encode("utf-8"), b""

        boundary = ToolExecutionBoundary(process_runner=mock_whatweb_runner)
        engine = LiveReconValidationEngine(tool_boundary=boundary)

        with patch.object(engine.tool_availability, "resolve_binary_path", return_value="/bin/whatweb"):
            rec = await engine._validate_whatweb(
                target="https://www.mitacsc.ac.in",
                campaign_id="p26-camp",
                auth_id="auth-valid",
                scope_validator=ScopeValidator(in_scope_assets=["www.mitacsc.ac.in"]),
                scope_hash="scope-hash-1",
            )
            assert rec.status == ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED
            assert rec.normalized_result_count == 3
            techs = {a["asset"] for a in rec.normalized_assets}
            assert "https://www.mitacsc.ac.in:apache" in techs
            assert "https://www.mitacsc.ac.in:php" in techs
            assert "https://www.mitacsc.ac.in:html5" in techs

    @pytest.mark.asyncio
    async def test_whatweb_aggressive_mode_rejected(self):
        """Aggressive scanning flags are rejected under policy."""
        engine = LiveReconValidationEngine()
        rec = await engine._validate_whatweb(
            target="https://www.mitacsc.ac.in",
            campaign_id="p26-camp",
            auth_id="auth-valid",
            scope_validator=ScopeValidator(in_scope_assets=["www.mitacsc.ac.in"]),
            scope_hash="scope-hash-1",
            custom_args=["-a", "3", "https://www.mitacsc.ac.in"],
        )
        assert rec.status == ToolValidationStatus.BLOCKED_POLICY
        assert "Aggressive WhatWeb scanning modes are forbidden" in rec.failure_reason

    @patch("backend.recon.recon_tool_availability.ReconToolAvailability.resolve_binary_path", return_value=None)
    @pytest.mark.asyncio
    async def test_whatweb_missing_binary_returns_binary_unavailable(self, mock_resolve):
        engine = LiveReconValidationEngine()
        rec = await engine._validate_whatweb(
            target="https://www.mitacsc.ac.in",
            campaign_id="p26-camp",
            auth_id="auth-valid",
            scope_validator=ScopeValidator(in_scope_assets=["www.mitacsc.ac.in"]),
            scope_hash="scope-hash-1",
        )
        assert rec.status == ToolValidationStatus.BINARY_UNAVAILABLE


# ==============================================================================
# 8. Policy-Gated & Stub Tools (Section 17, 18, 19, 20, 21)
# ==============================================================================

class TestPhase26PolicyGatedAndStubTools:
    """Explicit semantic status enforcement for stubs and active scanning tools."""

    def test_sublist3r_formally_stub_only(self):
        """Sublist3r must report STUB_ONLY / PRODUCTION_CAPABILITY_NOT_IMPLEMENTED."""
        engine = LiveReconValidationEngine()
        rec = engine._validate_sublist3r(
            target="https://www.mitacsc.ac.in",
            campaign_id="p26-camp",
            auth_id="auth-valid",
            scope_hash="scope-hash-1",
        )
        assert rec.status == ToolValidationStatus.STUB_ONLY
        assert "STUB_ONLY / PRODUCTION_CAPABILITY_NOT_IMPLEMENTED" in rec.failure_reason

    @patch("backend.recon.recon_tool_availability.ReconToolAvailability.resolve_binary_path", return_value=None)
    @pytest.mark.asyncio
    async def test_nmap_blocked_policy_without_port_scan_auth(self, mock_resolve):
        """Nmap is BLOCKED_POLICY unless explicit port scanning authorization is granted."""
        engine = LiveReconValidationEngine()
        rec = await engine._validate_nmap(
            base_domain="mitacsc.ac.in",
            target="https://www.mitacsc.ac.in",
            campaign_id="p26-camp",
            auth_id="auth-valid",
            allow_port_scan=False,
            scope_validator=ScopeValidator(in_scope_assets=["mitacsc.ac.in"]),
            scope_hash="scope-hash-1",
        )
        assert rec.status == ToolValidationStatus.BLOCKED_POLICY
        assert "Port scanning is not explicitly authorized" in rec.failure_reason

    @patch("backend.recon.recon_tool_availability.ReconToolAvailability.resolve_binary_path", return_value=None)
    @pytest.mark.asyncio
    async def test_gobuster_blocked_policy_without_dir_scan_auth(self, mock_resolve):
        """Gobuster is BLOCKED_POLICY unless directory fuzzing is explicitly permitted."""
        engine = LiveReconValidationEngine()
        rec = await engine._validate_gobuster(
            target="https://www.mitacsc.ac.in",
            campaign_id="p26-camp",
            auth_id="auth-valid",
            allow_dir_scan=False,
            scope_validator=ScopeValidator(in_scope_assets=["mitacsc.ac.in"]),
            scope_hash="scope-hash-1",
        )
        assert rec.status == ToolValidationStatus.BLOCKED_POLICY
        assert "Directory brute-forcing / fuzzing is not explicitly authorized" in rec.failure_reason

    def test_nuclei_and_dalfox_not_selected_recon_only(self):
        """Nuclei and Dalfox must report NOT_SELECTED_RECON_ONLY (no vulnerability scanning)."""
        engine = LiveReconValidationEngine()
        rec_nuclei = engine._validate_nuclei(
            target="https://www.mitacsc.ac.in",
            campaign_id="p26-camp",
            auth_id="auth-valid",
            scope_hash="scope-hash-1",
        )
        assert rec_nuclei.status == ToolValidationStatus.NOT_SELECTED_RECON_ONLY

        rec_dalfox = engine._validate_dalfox(
            target="https://www.mitacsc.ac.in",
            campaign_id="p26-camp",
            auth_id="auth-valid",
            scope_hash="scope-hash-1",
        )
        assert rec_dalfox.status == ToolValidationStatus.NOT_SELECTED_RECON_ONLY


# ==============================================================================
# 9. Controlled Validation Suite Integration Test (Section 11, 29)
# ==============================================================================

class TestPhase26FullSuiteIntegration:
    """Execute validation suite for https://www.mitacsc.ac.in and verify all invariants."""

    @pytest.mark.asyncio
    async def test_suite_execution_with_truthful_reporting(self, db_session):
        """Full suite runs and produces truthful statuses: zero fake LIVE_VALIDATED."""
        engine = LiveReconValidationEngine()
        
        # Patch all tools to return None for their binary path so they get BINARY_UNAVAILABLE
        # The suite will test the actual availability!
        with patch("backend.recon.recon_tool_availability.ReconToolAvailability.resolve_binary_path", return_value=None):
            res = await engine.execute_validation_suite(
                target="https://www.mitacsc.ac.in",
                campaign_id="camp-p26-mitacsc",
                authorization_record_id="auth-p26-valid",
                operator_confirmed=True,
                db_session=db_session,
                allow_port_scan=False,
                allow_dir_scan=False,
            )

        assert res.suite_status == "VALIDATION_COMPLETE"
        assert res.target == "https://www.mitacsc.ac.in"
        assert res.total_tools_evaluated == 13

        # Sublist3r MUST be STUB_ONLY
        assert res.tool_records["sublist3r"].status == ToolValidationStatus.STUB_ONLY

        # Nmap & Gobuster MUST be BLOCKED_POLICY
        assert res.tool_records["nmap"].status == ToolValidationStatus.BLOCKED_POLICY
        assert res.tool_records["gobuster"].status == ToolValidationStatus.BLOCKED_POLICY

        # Nuclei & Dalfox MUST be NOT_SELECTED_RECON_ONLY
        assert res.tool_records["nuclei"].status == ToolValidationStatus.NOT_SELECTED_RECON_ONLY
        assert res.tool_records["dalfox"].status == ToolValidationStatus.NOT_SELECTED_RECON_ONLY

        # Uninstalled CLI tools MUST report BINARY_UNAVAILABLE (truthful reporting, zero false success)
        for t in ["subfinder", "amass", "gau", "whatweb"]:
            assert res.tool_records[t].status == ToolValidationStatus.BINARY_UNAVAILABLE

        # Native providers (crtsh, dns_recon, http_probe, wayback) execute through boundary/engine
        assert res.recon_snapshot is not None
        assert res.attack_surface_graph is not None
        assert res.safety_audit_passed is True
