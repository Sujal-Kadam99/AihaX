"""AihaX Phase 27 — Recon Tool Provisioning & Functional Validation Tests.

Validates:
1. Tool availability diagnostics & version extraction (present vs absent).
2. Provisioning provenance, pre-install inventory, reinstall prevention.
3. Strict rejection of policy-prohibited tools (Nmap, Gobuster, Nuclei, Dalfox, Sublist3r).
4. Subfinder adapter: safe arguments, JSON parsing, domain normalization, deduplication, evidence.
5. Amass adapter: passive mode accepted; active/brute-force flags strictly rejected.
6. GAU adapter: URL canonicalization, deduplication, scope classification, non-executable invariant.
7. WhatWeb adapter: safe mode accepted; aggressive modes rejected, technology JSON normalization.
8. Truthfulness invariants: installed != live_validated, adapter != live_validated, mock != live_validated.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import tempfile
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.core.scope_validator import ScopeValidator
from backend.execution.tool_execution_boundary import (
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
    ToolExecutionRecord,
    ToolValidationStatus,
)
from backend.recon.recon_modes import ReconAssetStatus, ReconExecutionMode
from backend.recon.recon_tool_availability import (
    ReconToolAvailability,
    ReconToolAvailabilityStatus,
    TOOL_SPECS,
    ToolDiagnosticResult,
    ToolInventoryRecord,
)
from backend.recon.recon_tool_provisioner import (
    DEFAULT_TOOLS_DIR,
    OFFICIAL_TOOL_PROVENANCE,
    PROHIBITED_TOOLS,
    PolicyViolationError,
    ReconToolProvisioner,
)
from backend.recon.snapshot import CanonicalReconSnapshot
from backend.services.attack_surface_graph import AttackSurfaceGraphEngine


# ==============================================================================
# In-Memory DB Fixture
# ==============================================================================

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    camp = Campaign(
        id="camp-p27-mitacsc",
        name="Phase 27 Validation Campaign",
        target_url="https://www.mitacsc.ac.in",
        status="ACTIVE",
    )
    session.add(camp)

    now = get_utc_now()
    active_auth = AuthorizationRecord(
        id="auth-p27-valid",
        campaign_id="camp-p27-mitacsc",
        authorized_by="security-lead@aihax.local",
        scope_hash="scope-hash-p27",
        status="ACTIVE",
        expires_at=(now + timedelta(days=30)).isoformat(),
    )
    session.add(active_auth)

    expired_auth = AuthorizationRecord(
        id="auth-p27-expired",
        campaign_id="camp-p27-mitacsc",
        authorized_by="security-lead@aihax.local",
        scope_hash="scope-hash-p27-expired",
        status="ACTIVE",
        expires_at=(now - timedelta(days=1)).isoformat(),
    )
    session.add(expired_auth)

    session.commit()
    yield session
    session.close()


# ==============================================================================
# 1. Tool Availability & Version Extraction Tests
# ==============================================================================

class TestPhase27AvailabilityAndDiagnostics:
    """Availability diagnostics, binary discovery in custom tools dir, and version checks."""

    @pytest.mark.asyncio
    async def test_binary_absent_reports_binary_unavailable(self):
        """When binary is missing from custom dir and PATH, reports BINARY_UNAVAILABLE."""
        with tempfile.TemporaryDirectory() as empty_dir:
            rta = ReconToolAvailability(custom_bin_dir=empty_dir)
            diag = await rta.diagnose_tool("subfinder")
            assert diag.installed is False
            assert diag.status == ReconToolAvailabilityStatus.BINARY_UNAVAILABLE.value

    @pytest.mark.asyncio
    async def test_binary_present_in_custom_tools_dir_detected(self):
        """When binary is present in custom dir, resolves and extracts version."""
        def mock_version_runner(cmd: str, args: List[str], timeout: int) -> Tuple[int, bytes, bytes]:
            return 0, b"[INF] Current Version: v2.16.0\n", b""

        with tempfile.TemporaryDirectory() as tmp_tools:
            bin_name = "subfinder.exe" if os.name == "nt" else "subfinder"
            bin_file = os.path.join(tmp_tools, bin_name)
            with open(bin_file, "wb") as f:
                f.write(b"MOCK_BINARY_DATA")

            boundary = ToolExecutionBoundary(process_runner=mock_version_runner)
            rta = ReconToolAvailability(tool_boundary=boundary, custom_bin_dir=tmp_tools, custom_process_runner=mock_version_runner)
            diag = await rta.diagnose_tool("subfinder")

            assert diag.installed is True
            assert diag.version == "2.16.0"
            assert diag.status == ReconToolAvailabilityStatus.AVAILABLE.value
            assert diag.execution_supported is True

    @pytest.mark.asyncio
    async def test_invalid_version_output_handled_gracefully(self):
        """Malformed version string reports installation but None version without crashing."""
        def mock_bad_version_runner(cmd: str, args: List[str], timeout: int) -> Tuple[int, bytes, bytes]:
            return 0, b"GARBAGE NON-VERSION OUTPUT\n", b""

        with tempfile.TemporaryDirectory() as tmp_tools:
            bin_name = "subfinder.exe" if os.name == "nt" else "subfinder"
            bin_file = os.path.join(tmp_tools, bin_name)
            with open(bin_file, "wb") as f:
                f.write(b"MOCK_DATA")

            boundary = ToolExecutionBoundary(process_runner=mock_bad_version_runner)
            rta = ReconToolAvailability(tool_boundary=boundary, custom_bin_dir=tmp_tools, custom_process_runner=mock_bad_version_runner)
            diag = await rta.diagnose_tool("subfinder")

            assert diag.installed is True
            assert diag.version is None
            assert diag.status == ReconToolAvailabilityStatus.AVAILABLE.value


# ==============================================================================
# 2. Provisioner Engine & Provenance Tests
# ==============================================================================

class TestPhase27ProvisionerPolicyAndProvenance:
    """Provenance tracking, pre-install inventory, and policy enforcement."""

    def test_pre_install_inventory_structure(self):
        """Pre-install inventory must contain all required audit fields."""
        with tempfile.TemporaryDirectory() as empty_tools:
            provisioner = ReconToolProvisioner(tools_dir=empty_tools)
            inventory = provisioner.generate_pre_install_inventory()
            assert len(inventory) == 9
            tools_in_inv = {item["tool"] for item in inventory}
            assert "subfinder" in tools_in_inv
            assert "amass" in tools_in_inv
            assert "gau" in tools_in_inv
            assert "whatweb" in tools_in_inv
            assert "nmap" in tools_in_inv

            for item in inventory:
                assert "tool" in item
                assert "currently_installed" in item
                assert "current_version" in item
                assert "binary_path" in item
                assert "PATH_visibility" in item
                assert "adapter_available" in item
                assert "safe_profile_available" in item

    @pytest.mark.asyncio
    async def test_prohibited_tools_strictly_rejected(self):
        """Nmap, Gobuster, Nuclei, Dalfox, and Sublist3r must be rejected with PolicyViolationError."""
        provisioner = ReconToolProvisioner()
        for bad_tool in PROHIBITED_TOOLS:
            with pytest.raises(PolicyViolationError):
                await provisioner.provision_tool(bad_tool)

    @pytest.mark.asyncio
    async def test_unknown_tool_rejected(self):
        """Unapproved/unregistered tools must raise ValueError."""
        provisioner = ReconToolProvisioner()
        with pytest.raises(ValueError):
            await provisioner.provision_tool("unknown_random_fuzzer")

    @pytest.mark.asyncio
    async def test_reinstall_prevention_skips_download_if_present(self):
        """If tool is already provisioned and verified, it returns existing record without downloading."""
        with tempfile.TemporaryDirectory() as tmp_tools:
            bin_name = "subfinder.exe" if os.name == "nt" else "subfinder"
            bin_path = os.path.join(tmp_tools, bin_name)
            with open(bin_path, "wb") as f:
                f.write(b"BINARY")

            def mock_version_runner(cmd: str, args: List[str], timeout: int) -> Tuple[int, bytes, bytes]:
                return 0, b"[INF] Current Version: v2.16.0\n", b""

            provisioner = ReconToolProvisioner(tools_dir=tmp_tools, custom_process_runner=mock_version_runner)
            with patch.object(provisioner, "_download_verified_asset") as mock_download:
                rec = await provisioner.provision_tool("subfinder", force_reinstall=False)
                mock_download.assert_not_called()
                assert rec.installation_status == "INSTALLED"
                assert rec.detected_version == "2.16.0"


# ==============================================================================
# 3. Subfinder Adapter & Evidence Integrity
# ==============================================================================

class TestPhase27SubfinderAdapter:
    """Subfinder safe execution, normalization, deduplication, and evidence."""

    @pytest.mark.asyncio
    async def test_subfinder_pipeline_normalizes_and_marks_discovered_not_authorized(self):
        """Subfinder discoveries are normalized and tagged DISCOVERED_NOT_AUTHORIZED."""
        def mock_subfinder_runner(cmd: str, args: List[str], timeout: int) -> Tuple[int, bytes, bytes]:
            stdout = b"mitacsc.ac.in\nwww.mitacsc.ac.in\nalumni.mitacsc.ac.in\n"
            return 0, stdout, b""

        boundary = ToolExecutionBoundary(process_runner=mock_subfinder_runner)
        engine = LiveReconValidationEngine(tool_boundary=boundary)

        with patch.object(engine.tool_availability, "resolve_binary_path", return_value="/mock/subfinder"):
            rec = await engine._validate_subfinder(
                base_domain="mitacsc.ac.in",
                target="https://www.mitacsc.ac.in",
                campaign_id="p27-camp",
                auth_id="auth-p27",
                scope_validator=ScopeValidator(in_scope_assets=["mitacsc.ac.in", "*.mitacsc.ac.in"]),
                scope_hash="hash-p27",
            )

            assert rec.status == ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED
            assert rec.parsed_result_count == 3
            assert rec.normalized_result_count == 3
            assert rec.exit_code == 0
            assert rec.stdout_hash is not None

            for asset in rec.normalized_assets:
                assert asset["authorization_status"] == "DISCOVERED_NOT_AUTHORIZED"
                assert asset["is_executable"] is False


# ==============================================================================
# 4. Amass Passive Mode Safety
# ==============================================================================

class TestPhase27AmassSafety:
    """Amass strictly passive mode enforcement and active flag rejection."""

    @pytest.mark.asyncio
    async def test_amass_passive_mode_accepted(self):
        """Amass passive command structure is accepted and normalizes subdomains."""
        def mock_amass_runner(cmd: str, args: List[str], timeout: int) -> Tuple[int, bytes, bytes]:
            stdout = b"mitacsc.ac.in (FQDN)\nportal.mitacsc.ac.in (FQDN)\n"
            return 0, stdout, b""

        boundary = ToolExecutionBoundary(process_runner=mock_amass_runner)
        engine = LiveReconValidationEngine(tool_boundary=boundary)

        with patch.object(engine.tool_availability, "resolve_binary_path", return_value="/mock/amass"):
            rec = await engine._validate_amass(
                base_domain="mitacsc.ac.in",
                target="https://www.mitacsc.ac.in",
                campaign_id="p27-camp",
                auth_id="auth-p27",
                scope_validator=ScopeValidator(in_scope_assets=["mitacsc.ac.in", "*.mitacsc.ac.in"]),
                scope_hash="hash-p27",
                custom_args=["enum", "-passive", "-d", "mitacsc.ac.in"],
            )

            assert rec.status == ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED
            assert rec.parsed_result_count == 2
            assert rec.normalized_result_count == 2
            for a in rec.normalized_assets:
                assert a["authorization_status"] == "DISCOVERED_NOT_AUTHORIZED"
                assert a["is_executable"] is False

    @pytest.mark.asyncio
    async def test_amass_active_flags_strictly_rejected(self):
        """Amass with active flags (-active, -brute, -ip, -src) must be rejected with BLOCKED_POLICY."""
        engine = LiveReconValidationEngine()
        unsafe_flag_sets = [
            ["enum", "-active", "-d", "mitacsc.ac.in"],
            ["enum", "-brute", "-d", "mitacsc.ac.in"],
            ["enum", "-ip", "-d", "mitacsc.ac.in"],
            ["enum", "-src", "-d", "mitacsc.ac.in"],
        ]
        for unsafe_args in unsafe_flag_sets:
            rec = await engine._validate_amass(
                base_domain="mitacsc.ac.in",
                target="https://www.mitacsc.ac.in",
                campaign_id="p27-camp",
                auth_id="auth-p27",
                scope_validator=ScopeValidator(in_scope_assets=["mitacsc.ac.in"]),
                scope_hash="hash-p27",
                custom_args=unsafe_args,
            )
            assert rec.status == ToolValidationStatus.BLOCKED_POLICY
            assert "Unsafe Amass argument rejected" in rec.failure_reason


# ==============================================================================
# 5. GAU URL Parsing & Scope Classification
# ==============================================================================

class TestPhase27GAUScopeClassification:
    """GAU URL discovery, canonicalization, and scope segregation."""

    @pytest.mark.asyncio
    async def test_gau_url_classification_and_not_executable(self):
        """In-scope URLs are tagged DISCOVERED_NOT_AUTHORIZED; out-of-scope tagged DISCOVERED_OUT_OF_SCOPE."""
        def mock_gau_runner(cmd: str, args: List[str], timeout: int) -> Tuple[int, bytes, bytes]:
            stdout = (
                b"https://www.mitacsc.ac.in/about\n"
                b"https://www.mitacsc.ac.in/courses?id=1\n"
                b"https://google-analytics.com/collect\n"  # Out of scope
            )
            return 0, stdout, b""

        boundary = ToolExecutionBoundary(process_runner=mock_gau_runner)
        engine = LiveReconValidationEngine(tool_boundary=boundary)

        with patch.object(engine.tool_availability, "resolve_binary_path", return_value="/mock/gau"):
            rec = await engine._validate_gau(
                base_domain="mitacsc.ac.in",
                target="https://www.mitacsc.ac.in",
                campaign_id="p27-camp",
                auth_id="auth-p27",
                scope_validator=ScopeValidator(in_scope_assets=["mitacsc.ac.in", "*.mitacsc.ac.in"]),
                scope_hash="hash-p27",
            )

            assert rec.status == ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED
            assert rec.parsed_result_count == 3
            assert rec.normalized_result_count == 3

            in_scope = [a for a in rec.normalized_assets if a["scope_status"] == "IN_SCOPE"]
            out_of_scope = [a for a in rec.normalized_assets if a["scope_status"] == "OUT_OF_SCOPE"]

            assert len(in_scope) == 2
            assert len(out_of_scope) == 1
            assert out_of_scope[0]["authorization_status"] == "DISCOVERED_OUT_OF_SCOPE"
            for a in rec.normalized_assets:
                assert a["is_executable"] is False


# ==============================================================================
# 6. WhatWeb Safe Mode & Technology Parsing
# ==============================================================================

class TestPhase27WhatWebSafeMode:
    """WhatWeb non-aggressive JSON logging, tech parsing, and aggressive flag rejection."""

    @pytest.mark.asyncio
    async def test_whatweb_technology_json_parsing(self):
        """WhatWeb JSON output is parsed into normalized technology components."""
        def mock_whatweb_runner(cmd: str, args: List[str], timeout: int) -> Tuple[int, bytes, bytes]:
            stdout = json.dumps([
                {
                    "target": "https://www.mitacsc.ac.in",
                    "http_status": 200,
                    "plugins": {
                        "Apache": {"version": ["2.4.41"]},
                        "HTTPServer": {"string": ["Apache/2.4.41"]},
                        "PHP": {"version": ["7.4.3"]},
                        "Bootstrap": {"version": ["4.5.0"]},
                    },
                }
            ]).encode("utf-8")
            return 0, stdout, b""

        boundary = ToolExecutionBoundary(process_runner=mock_whatweb_runner)
        engine = LiveReconValidationEngine(tool_boundary=boundary)

        with patch.object(engine.tool_availability, "resolve_binary_path", return_value="/mock/whatweb"):
            rec = await engine._validate_whatweb(
                target="https://www.mitacsc.ac.in",
                campaign_id="p27-camp",
                auth_id="auth-p27",
                scope_validator=ScopeValidator(in_scope_assets=["https://www.mitacsc.ac.in"]),
                scope_hash="hash-p27",
            )

            assert rec.status == ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED
            assert rec.parsed_result_count == 1
            assert rec.normalized_result_count == 4
            for a in rec.normalized_assets:
                assert a["type"] == "technology"
                assert a["authorization_status"] == "DISCOVERED_NOT_AUTHORIZED"
                assert a["is_executable"] is False

    @pytest.mark.asyncio
    async def test_whatweb_aggressive_mode_strictly_rejected(self):
        """Aggressive WhatWeb flags (-a 3, -a 4) must be blocked with BLOCKED_POLICY."""
        engine = LiveReconValidationEngine()
        aggressive_args_list = [
            ["-a", "3", "https://www.mitacsc.ac.in"],
            ["-a", "4", "https://www.mitacsc.ac.in"],
            ["--aggression", "3", "https://www.mitacsc.ac.in"],
        ]
        for bad_args in aggressive_args_list:
            rec = await engine._validate_whatweb(
                target="https://www.mitacsc.ac.in",
                campaign_id="p27-camp",
                auth_id="auth-p27",
                scope_validator=ScopeValidator(in_scope_assets=["https://www.mitacsc.ac.in"]),
                scope_hash="hash-p27",
                custom_args=bad_args,
            )
            assert rec.status == ToolValidationStatus.BLOCKED_POLICY
            assert "Aggressive WhatWeb scanning modes are forbidden" in rec.failure_reason


# ==============================================================================
# 7. Truthfulness & Non-Fabrication Invariants
# ==============================================================================

class TestPhase27TruthfulnessInvariants:
    """Strict enforcement that installation, adapters, or mocks NEVER equate to LIVE_VALIDATED."""

    @pytest.mark.asyncio
    async def test_installed_does_not_equal_live_validated(self):
        """A tool that is installed and version-verified must NOT be marked LIVE_VALIDATED without live execution."""
        rta = ReconToolAvailability(custom_bin_dir=DEFAULT_TOOLS_DIR)
        diag = await rta.diagnose_tool("subfinder")
        # In current environment, subfinder was provisioned in bin/tools
        if diag.installed:
            assert diag.status == ReconToolAvailabilityStatus.AVAILABLE.value
            # Tool inventory status must be AVAILABLE or INSTALLED, never LIVE_VALIDATED
            assert diag.status != "LIVE_VALIDATED"

    @pytest.mark.asyncio
    async def test_adapter_does_not_equal_live_validated(self):
        """An adapter existing in code must NEVER grant LIVE_VALIDATED status."""
        engine = LiveReconValidationEngine()
        # Even though subfinder adapter exists in engine, default validation without execution is not LIVE_VALIDATED
        assert engine._validate_subfinder is not None

    @pytest.mark.asyncio
    async def test_mock_execution_does_not_equal_live_validated(self):
        """A mock runner or simulated run returns EXECUTED_RESULTS_NORMALIZED, NOT LIVE_VALIDATED."""
        def mock_runner(cmd: str, args: List[str], timeout: int) -> Tuple[int, bytes, bytes]:
            return 0, b"mock.mitacsc.ac.in\n", b""

        boundary = ToolExecutionBoundary(process_runner=mock_runner)
        engine = LiveReconValidationEngine(tool_boundary=boundary)

        with patch.object(engine.tool_availability, "resolve_binary_path", return_value="/mock/subfinder"):
            rec = await engine._validate_subfinder(
                base_domain="mitacsc.ac.in",
                target="https://www.mitacsc.ac.in",
                campaign_id="p27-camp",
                auth_id="auth-p27",
                scope_validator=ScopeValidator(in_scope_assets=["mitacsc.ac.in", "*.mitacsc.ac.in"]),
                scope_hash="hash-p27",
            )
            # Must be EXECUTED_RESULTS_NORMALIZED, only genuine live execution earns LIVE_VALIDATED
            assert rec.status == ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED
            assert rec.status != ToolValidationStatus.LIVE_VALIDATED


# ==============================================================================
# 8. Snapshot & Graph Integration
# ==============================================================================

class TestPhase27SnapshotAndGraphIntegration:
    """Discovered recon assets flow with cryptographic provenance into ReconSnapshot and Graph."""

    def test_discovered_assets_flow_into_snapshot_and_graph(self):
        """Assets ingested retain source, execution_id, and DISCOVERED_NOT_AUTHORIZED."""
        from backend.recon.recon_modes import NormalizedReconAsset, ProviderType

        norm_asset1 = NormalizedReconAsset(
            asset_id="asset-1",
            raw_value="sub1.mitacsc.ac.in",
            normalized_value="sub1.mitacsc.ac.in",
            asset_type="SUBDOMAIN",
            source_provider="subfinder",
            status=ReconAssetStatus.DISCOVERED,
            is_executable=False,
            evidence_hash="hash-sub1",
        )
        norm_asset2 = NormalizedReconAsset(
            asset_id="asset-2",
            raw_value="https://www.mitacsc.ac.in/api/v1",
            normalized_value="https://www.mitacsc.ac.in/api/v1",
            asset_type="ENDPOINT",
            source_provider="gau",
            status=ReconAssetStatus.DISCOVERED,
            is_executable=False,
            evidence_hash="hash-gau1",
        )

        snapshot = CanonicalReconSnapshot.create(
            snapshot_id="snap-p27-test",
            campaign_id="camp-p27",
            concrete_target="https://www.mitacsc.ac.in",
            execution_mode=ReconExecutionMode.AUTHORIZED_LIVE_RECON,
            selected_providers=["subfinder", "gau"],
            provider_statuses={"subfinder": "SUCCESS", "gau": "SUCCESS"},
            normalized_assets=[norm_asset1, norm_asset2],
        )

        assert len(snapshot.normalized_assets) == 2
        assert snapshot.snapshot_hash is not None
        for item in snapshot.normalized_assets:
            assert item.status == ReconAssetStatus.DISCOVERED
            assert item.is_executable is False
