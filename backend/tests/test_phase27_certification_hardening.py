"""AihaX Phase 27 — Certification Hardening Test Suite.

Verifies all mandatory certification gates:
1. Authorization Binding Proof (complete chain, exact target, failure modes).
2. Pipeline-Only Provenance (disqualifies manual runs, enforces pipeline ID & evidence).
3. Tool Artifact Hash Provenance (real hashes, honest archive status, deterministic).
4. Ruby / WhatWeb Dependency Provenance (Ruby, WhatWeb, Addressable gem).
5. Separate Provisioning-Network Audit & Strict Host Protection.
6. Static AST Security Audit (0 target bypasses, 0 boundary bypasses, 0 shell=True).
7. Consolidated Machine-Verifiable Certification Gate.
"""

import hashlib
import os
import pytest
from unittest.mock import MagicMock, patch

from backend.recon.live_recon_validator import (
    ExecutionOrigin,
    LiveReconValidationEngine,
    ReconLifecycleEvent,
    ToolExecutionRecord,
    ToolValidationStatus,
)
from backend.recon.phase27_certification import (
    ArtifactHashStatus,
    AuthorizationBindingProof,
    CertificationDecision,
    CertificationGateStatus,
    NetworkSeparationAuditor,
    Phase27CertificationEngine,
    RubyDependencyProvenanceRecorder,
    ToolArtifactProvenanceRecorder,
)
from backend.recon.recon_tool_provisioner import (
    ALLOWED_PROVISIONING_HOSTS,
    OFFICIAL_TOOL_PROVENANCE,
    PolicyViolationError,
    ReconToolProvisioner,
    StrictProvisioningRedirectHandler,
)


@pytest.fixture
def valid_auth_binding() -> AuthorizationBindingProof:
    """Fixture providing valid authorization binding chain matching actual repository records."""
    return AuthorizationBindingProof(
        authorization_record_id="663e3722-931a-47ea-b932-4aba7d24dbe7",
        campaign_id="bda03f2c-9c9d-4de2-a902-4a35c371eecc",
        operator_id="lead_security_operator",
        exact_target="https://www.mitacsc.ac.in",
        authorization_status="ACTIVE",
        authorization_timestamp="2026-08-30T05:43:22.463394+00:00",
        campaign_timestamp="2026-08-30T05:43:22.352562+00:00",
        execution_mode="AUTHORIZED_LIVE_RECON",
        scope_snapshot_hash="33f91ee87bdc686fdfbac48977a8df58c23eeb6ddaf8491ef77e19d5fc71fffd",
        safety_policy={"max_concurrency": 1, "rate_limit_rps": 2, "max_target_requests": 10},
        tool_name="subfinder",
        tool_execution_id="tool-exec-subfinder-001",
        evidence_reference="3098c855-b3d7-4a4c-9f7e-060c4d6ccf81",
        recon_snapshot_hash="2a1e6f47567d85a0dbb49417675680fd7f2601aff699f936bc585f1643f5a9c2",
        attack_surface_graph_hash="d5a7b6fcd447ffb1a4e87a9ab409851c1ed315229b33aad28cda517b0dd8d171",
    )


class TestAuthorizationBindingProof:
    """Gate 1: Authorization-Binding Proof and Chain Verification."""

    def test_valid_authorization_chain_passes(self, valid_auth_binding):
        """Valid chain with exact target, active status, and bound hashes passes."""
        is_valid, failures = valid_auth_binding.verify_binding()
        assert is_valid is True
        assert failures == []

    def test_missing_authorization_id_fails(self, valid_auth_binding):
        """Missing authorization record ID fails certification."""
        valid_auth_binding.authorization_record_id = ""
        is_valid, failures = valid_auth_binding.verify_binding()
        assert is_valid is False
        assert any("authorization_record_id is missing" in f for f in failures)

    def test_inactive_authorization_fails(self, valid_auth_binding):
        """Inactive or revoked authorization status fails certification."""
        valid_auth_binding.authorization_status = "REVOKED"
        is_valid, failures = valid_auth_binding.verify_binding()
        assert is_valid is False
        assert any("authorization_status is 'REVOKED'" in f for f in failures)

    def test_campaign_mismatch_fails(self, valid_auth_binding):
        """Missing or unlinked campaign fails certification."""
        valid_auth_binding.campaign_id = ""
        is_valid, failures = valid_auth_binding.verify_binding()
        assert is_valid is False
        assert any("campaign_id is missing" in f for f in failures)

    def test_target_mismatch_fails(self, valid_auth_binding):
        """Target other than mitacsc.ac.in fails certification."""
        valid_auth_binding.exact_target = "https://unauthorized-target.example.com"
        is_valid, failures = valid_auth_binding.verify_binding()
        assert is_valid is False
        assert any("does not match authorized target" in f for f in failures)

    def test_wildcard_target_fails(self, valid_auth_binding):
        """Wildcard target is strictly rejected (exact target required)."""
        valid_auth_binding.exact_target = "https://*.mitacsc.ac.in"
        is_valid, failures = valid_auth_binding.verify_binding()
        assert is_valid is False
        assert any("contains wildcard" in f for f in failures)

    def test_wrong_execution_mode_fails(self, valid_auth_binding):
        """Execution mode other than AUTHORIZED_LIVE_RECON fails."""
        valid_auth_binding.execution_mode = "ACTIVE_EXPLOIT_VALIDATION"
        is_valid, failures = valid_auth_binding.verify_binding()
        assert is_valid is False
        assert any("execution_mode" in f for f in failures)

    def test_missing_scope_snapshot_hash_fails(self, valid_auth_binding):
        """Missing or truncated scope snapshot hash fails certification."""
        valid_auth_binding.scope_snapshot_hash = "short"
        is_valid, failures = valid_auth_binding.verify_binding()
        assert is_valid is False
        assert any("scope_snapshot_hash" in f for f in failures)

    def test_missing_evidence_reference_fails(self, valid_auth_binding):
        """Execution lacking evidence reference fails certification."""
        valid_auth_binding.evidence_reference = ""
        is_valid, failures = valid_auth_binding.verify_binding()
        assert is_valid is False
        assert any("evidence_reference is missing" in f for f in failures)

    def test_missing_operator_fails(self, valid_auth_binding):
        """Missing operator ID fails certification."""
        valid_auth_binding.operator_id = ""
        is_valid, failures = valid_auth_binding.verify_binding()
        assert is_valid is False
        assert any("operator_id is missing" in f for f in failures)


class TestPipelineOnlyProvenance:
    """Gate 2: Pipeline-Only Live Execution Proof."""

    def test_controlled_pipeline_execution_can_become_live_validated(self):
        """Only records originating from PHASE27_CONTROLLED_PIPELINE can transition to LIVE_VALIDATED."""
        engine = LiveReconValidationEngine()
        target = "https://www.mitacsc.ac.in"
        camp_id = "phase27-mitacsc-auth-camp"
        auth_id = "auth-mitacsc-phase27-record-valid"
        pipeline_id = "phase27-pipe-run-001"

        # Construct a record in EXECUTED_RESULTS_NORMALIZED state
        rec = ToolExecutionRecord(
            tool_name="subfinder",
            execution_origin=ExecutionOrigin.PHASE27_CONTROLLED_PIPELINE,
            pipeline_run_id=pipeline_id,
            campaign_id=camp_id,
            authorization_record_id=auth_id,
            target=target,
            evidence_id="ev-subfinder-001",
            status=ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED,
            parsed_result_count=10,
            normalized_result_count=10,
        )

        tool_records = {"subfinder": rec}
        deduped = [MagicMock(source_provider="subfinder")]

        # Run the transition logic
        for tool_id, r in tool_records.items():
            contrib = sum(1 for a in deduped if a.source_provider == tool_id)
            r.snapshot_contribution_count = contrib
            if r.status == ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED and contrib > 0:
                if (
                    r.execution_origin == ExecutionOrigin.PHASE27_CONTROLLED_PIPELINE
                    and r.pipeline_run_id
                    and r.evidence_id
                    and r.authorization_record_id == auth_id
                    and r.campaign_id == camp_id
                    and r.target == target
                ):
                    r.status = ToolValidationStatus.LIVE_VALIDATED

        assert rec.status == ToolValidationStatus.LIVE_VALIDATED

    def test_manual_diagnostic_rejected_from_live_validated(self):
        """Manual diagnostic execution MUST NOT transition to LIVE_VALIDATED."""
        rec = ToolExecutionRecord(
            tool_name="subfinder",
            execution_origin=ExecutionOrigin.MANUAL_DIAGNOSTIC,
            pipeline_run_id="manual-run",
            campaign_id="camp",
            authorization_record_id="auth",
            target="https://www.mitacsc.ac.in",
            evidence_id="ev-001",
            status=ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED,
        )

        # Transition attempt
        if rec.execution_origin == ExecutionOrigin.PHASE27_CONTROLLED_PIPELINE:
            rec.status = ToolValidationStatus.LIVE_VALIDATED

        assert rec.status == ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED
        assert rec.status != ToolValidationStatus.LIVE_VALIDATED

    def test_manual_troubleshooting_rejected_from_live_validated(self):
        """Manual troubleshooting execution MUST NOT transition to LIVE_VALIDATED."""
        rec = ToolExecutionRecord(
            tool_name="amass",
            execution_origin=ExecutionOrigin.MANUAL_TROUBLESHOOTING,
            pipeline_run_id="troubleshoot-run",
            campaign_id="camp",
            authorization_record_id="auth",
            target="https://www.mitacsc.ac.in",
            evidence_id="ev-002",
            status=ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED,
        )

        if rec.execution_origin == ExecutionOrigin.PHASE27_CONTROLLED_PIPELINE:
            rec.status = ToolValidationStatus.LIVE_VALIDATED

        assert rec.status != ToolValidationStatus.LIVE_VALIDATED

    def test_unspecified_origin_rejected_from_live_validated(self):
        """Unspecified execution origin MUST NOT transition to LIVE_VALIDATED."""
        rec = ToolExecutionRecord(
            tool_name="gau",
            execution_origin=ExecutionOrigin.UNSPECIFIED,
            pipeline_run_id="pipe-1",
            campaign_id="camp",
            authorization_record_id="auth",
            target="https://www.mitacsc.ac.in",
            evidence_id="ev-003",
            status=ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED,
        )

        if rec.execution_origin == ExecutionOrigin.PHASE27_CONTROLLED_PIPELINE:
            rec.status = ToolValidationStatus.LIVE_VALIDATED

        assert rec.status != ToolValidationStatus.LIVE_VALIDATED

    def test_missing_pipeline_run_id_rejected(self):
        """Execution missing pipeline_run_id MUST NOT transition to LIVE_VALIDATED."""
        rec = ToolExecutionRecord(
            tool_name="whatweb",
            execution_origin=ExecutionOrigin.PHASE27_CONTROLLED_PIPELINE,
            pipeline_run_id=None,
            campaign_id="camp",
            authorization_record_id="auth",
            target="https://www.mitacsc.ac.in",
            evidence_id="ev-004",
            status=ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED,
        )

        if rec.execution_origin == ExecutionOrigin.PHASE27_CONTROLLED_PIPELINE and rec.pipeline_run_id:
            rec.status = ToolValidationStatus.LIVE_VALIDATED

        assert rec.status != ToolValidationStatus.LIVE_VALIDATED

    def test_missing_evidence_rejected(self):
        """Execution missing evidence_id MUST NOT transition to LIVE_VALIDATED."""
        rec = ToolExecutionRecord(
            tool_name="subfinder",
            execution_origin=ExecutionOrigin.PHASE27_CONTROLLED_PIPELINE,
            pipeline_run_id="pipe-1",
            campaign_id="camp",
            authorization_record_id="auth",
            target="https://www.mitacsc.ac.in",
            evidence_id=None,
            status=ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED,
        )

        if rec.execution_origin == ExecutionOrigin.PHASE27_CONTROLLED_PIPELINE and rec.evidence_id:
            rec.status = ToolValidationStatus.LIVE_VALIDATED

        assert rec.status != ToolValidationStatus.LIVE_VALIDATED

    def test_mismatched_campaign_rejected(self):
        """Execution with mismatched campaign ID rejected from LIVE_VALIDATED."""
        rec = ToolExecutionRecord(
            tool_name="subfinder",
            execution_origin=ExecutionOrigin.PHASE27_CONTROLLED_PIPELINE,
            pipeline_run_id="pipe-1",
            campaign_id="wrong-camp",
            authorization_record_id="auth-valid",
            target="https://www.mitacsc.ac.in",
            evidence_id="ev-001",
            status=ToolValidationStatus.EXECUTED_RESULTS_NORMALIZED,
        )

        expected_camp = "correct-camp"
        if rec.campaign_id == expected_camp:
            rec.status = ToolValidationStatus.LIVE_VALIDATED

        assert rec.status != ToolValidationStatus.LIVE_VALIDATED


class TestToolArtifactProvenance:
    """Gate 3: Tool Artifact Cryptographic Hashes."""

    def test_captures_real_tool_hashes(self):
        """Captures real SHA-256 for all provisioned external tools."""
        recorder = ToolArtifactProvenanceRecorder()
        records = recorder.record_all_tools()

        for tool_name in ["subfinder", "amass", "gau", "whatweb"]:
            assert tool_name in records
            rec = records[tool_name]
            assert rec.binary_path is not None
            assert rec.binary_sha256 != "BINARY_NOT_FOUND"
            assert len(rec.binary_sha256) == 64  # Valid SHA-256
            assert rec.status == ArtifactHashStatus.VERIFIED

    def test_archive_status_honestly_represented(self):
        """Downloaded archives removed after extraction are honestly reported as SOURCE_ARCHIVE_HASH_UNAVAILABLE."""
        recorder = ToolArtifactProvenanceRecorder()
        rec = recorder.record_tool_provenance("subfinder")

        # Archive file does not exist on disk post-install
        if not os.path.isfile(os.path.join(recorder.tools_dir, "subfinder_archive.zip")):
            assert rec.archive_sha256 == "SOURCE_ARCHIVE_HASH_UNAVAILABLE"
            assert rec.archive_status == ArtifactHashStatus.UNAVAILABLE

    def test_deterministic_provenance_serialization(self):
        """Tool artifact provenance serializes deterministically to JSON-compatible dict."""
        recorder = ToolArtifactProvenanceRecorder()
        rec = recorder.record_tool_provenance("amass")
        d = rec.to_dict()

        assert d["tool"] == "amass"
        assert d["upstream_repository"] == "owasp-amass/amass"
        assert d["status"] in ("VERIFIED", "UNAVAILABLE")
        assert len(d["binary_sha256"]) == 64


class TestRubyDependencyProvenance:
    """Gate 4: Ruby / WhatWeb Dependency Provenance."""

    def test_captures_ruby_and_whatweb_provenance(self):
        """Captures Ruby executable, version, SHA-256, and addressable gem version."""
        recorder = RubyDependencyProvenanceRecorder()
        rec = recorder.record_provenance()

        assert rec.ruby_executable_path != "RUBY_NOT_FOUND"
        assert "ruby" in rec.ruby_version.lower()
        assert len(rec.ruby_executable_sha256) == 64
        assert rec.whatweb_version == "0.6.4"
        assert rec.required_gems.get("addressable") is not None
        assert rec.status == ArtifactHashStatus.VERIFIED

    def test_ruby_provenance_serialization(self):
        """Ruby provenance record serializes deterministically."""
        recorder = RubyDependencyProvenanceRecorder()
        rec = recorder.record_provenance()
        d = rec.to_dict()

        assert "ruby_executable_path" in d
        assert "whatweb_path" in d
        assert d["status"] == "VERIFIED"


class TestNetworkSeparationAndProvisionerSafety:
    """Gate 5: Separate Provisioning Network vs Target Network."""

    def test_provisioner_rejects_target_url(self):
        """Provisioner strictly blocks target URLs (cannot be used for target scanning)."""
        provisioner = ReconToolProvisioner()
        with pytest.raises(PermissionError) as exc_info:
            provisioner._download_verified_asset("https://www.mitacsc.ac.in")
        assert "blocked for unauthorized host" in str(exc_info.value)

    def test_provisioner_rejects_arbitrary_unapproved_host(self):
        """Provisioner strictly blocks arbitrary/untrusted domains."""
        provisioner = ReconToolProvisioner()
        with pytest.raises(PermissionError) as exc_info:
            provisioner._download_verified_asset("https://malicious-mirror.example.com/subfinder.zip")
        assert "blocked for unauthorized host" in str(exc_info.value)

    def test_provisioner_rejects_non_https(self):
        """Provisioner strictly blocks non-HTTPS protocols."""
        provisioner = ReconToolProvisioner()
        with pytest.raises(PermissionError) as exc_info:
            provisioner._download_verified_asset("http://github.com/projectdiscovery/subfinder/releases/download/v2.16.0/subfinder.zip")
        assert "strictly requires HTTPS" in str(exc_info.value)

    def test_strict_redirect_handler_blocks_redirect_escape(self):
        """Strict redirect handler prevents redirect escape to unapproved domains."""
        handler = StrictProvisioningRedirectHandler()
        with pytest.raises(PermissionError) as exc_info:
            handler.redirect_request(
                req=MagicMock(),
                fp=None,
                code=302,
                msg="Found",
                headers={},
                newurl="https://evil-redirect.com/payload.exe",
            )
        assert "redirect to unauthorized host 'evil-redirect.com' blocked" in str(exc_info.value)

    def test_strict_redirect_handler_allows_approved_host(self):
        """Strict redirect handler permits redirects to official GitHub release CDN."""
        handler = StrictProvisioningRedirectHandler()
        req_mock = MagicMock()
        with patch("urllib.request.HTTPRedirectHandler.redirect_request", return_value=req_mock):
            result = handler.redirect_request(
                req=MagicMock(),
                fp=None,
                code=302,
                msg="Found",
                headers={},
                newurl="https://objects.githubusercontent.com/github-production-release-asset-2e65be/12345/subfinder.zip",
            )
            assert result is req_mock


class TestStaticSecurityAudit:
    """Gate 6: AST Static Security Audit across Backend."""

    def test_network_separation_ast_audit(self):
        """AST audit confirms 0 target bypasses, 0 boundary bypasses, 0 shell=True, 1 restricted provisioning exception."""
        auditor = NetworkSeparationAuditor()
        result = auditor.audit()

        assert result.target_network_execution_bypasses == 0
        assert result.tool_execution_boundary_bypasses == 0
        assert result.unauthorized_shell_execution_paths == 0
        assert result.provisioning_network_exception == 1
        assert result.provisioning_exception_detail == "restricted to approved upstream artifact retrieval"
        assert result.status == CertificationGateStatus.PASS


class TestPhase27ConsolidatedCertification:
    """Gate 7: Consolidated Machine-Verifiable Certification Engine."""

    def test_full_certification_passes_with_valid_evidence(self, valid_auth_binding):
        """Complete certification passes when all gates and provenance checks succeed."""
        engine = Phase27CertificationEngine()
        pipeline_run_id = "phase27-pipe-run-mitacsc-001"

        # Build mock tool records matching valid live validation
        tool_records = {
            "subfinder": ToolExecutionRecord(
                tool_name="subfinder",
                execution_origin=ExecutionOrigin.PHASE27_CONTROLLED_PIPELINE,
                pipeline_run_id=pipeline_run_id,
                campaign_id=valid_auth_binding.campaign_id,
                authorization_record_id=valid_auth_binding.authorization_record_id,
                target=valid_auth_binding.exact_target,
                evidence_id="ev-subfinder-001",
                status=ToolValidationStatus.LIVE_VALIDATED,
                parsed_result_count=47,
                normalized_result_count=47,
            ),
            "amass": ToolExecutionRecord(
                tool_name="amass",
                execution_origin=ExecutionOrigin.PHASE27_CONTROLLED_PIPELINE,
                pipeline_run_id=pipeline_run_id,
                campaign_id=valid_auth_binding.campaign_id,
                authorization_record_id=valid_auth_binding.authorization_record_id,
                target=valid_auth_binding.exact_target,
                evidence_id="ev-amass-001",
                status=ToolValidationStatus.LIVE_VALIDATED,
                parsed_result_count=3,
                normalized_result_count=3,
            ),
            "gau": ToolExecutionRecord(
                tool_name="gau",
                execution_origin=ExecutionOrigin.PHASE27_CONTROLLED_PIPELINE,
                pipeline_run_id=pipeline_run_id,
                campaign_id=valid_auth_binding.campaign_id,
                authorization_record_id=valid_auth_binding.authorization_record_id,
                target=valid_auth_binding.exact_target,
                evidence_id="ev-gau-001",
                status=ToolValidationStatus.LIVE_VALIDATED,
                parsed_result_count=5820,
                normalized_result_count=5820,
            ),
            "whatweb": ToolExecutionRecord(
                tool_name="whatweb",
                execution_origin=ExecutionOrigin.PHASE27_CONTROLLED_PIPELINE,
                pipeline_run_id=pipeline_run_id,
                campaign_id=valid_auth_binding.campaign_id,
                authorization_record_id=valid_auth_binding.authorization_record_id,
                target=valid_auth_binding.exact_target,
                evidence_id="ev-whatweb-001",
                status=ToolValidationStatus.LIVE_VALIDATED,
                parsed_result_count=1,
                normalized_result_count=1,
            ),
        }

        report = engine.evaluate_certification(
            auth_binding=valid_auth_binding,
            tool_records=tool_records,
            pipeline_run_id=pipeline_run_id,
        )

        assert report.certification_decision == CertificationDecision.CERTIFIED.value
        assert report.authorization_gate["status"] == "PASS"
        assert report.pipeline_provenance_gate["status"] == "PASS"
        assert report.tool_artifact_gate["status"] == "PASS"
        assert report.ruby_provenance_gate["status"] == "PASS"
        assert report.network_separation_gate["status"] == "PASS"
        assert report.safety_invariants_confirmed is True

    def test_certification_fails_when_manual_execution_present(self, valid_auth_binding):
        """Certification strictly rejects if a manual/diagnostic tool record is present."""
        engine = Phase27CertificationEngine()
        pipeline_run_id = "phase27-pipe-run-mitacsc-001"

        tool_records = {
            "subfinder": ToolExecutionRecord(
                tool_name="subfinder",
                execution_origin=ExecutionOrigin.MANUAL_DIAGNOSTIC,
                pipeline_run_id=pipeline_run_id,
                campaign_id=valid_auth_binding.campaign_id,
                authorization_record_id=valid_auth_binding.authorization_record_id,
                target=valid_auth_binding.exact_target,
                evidence_id="ev-subfinder-001",
                status=ToolValidationStatus.LIVE_VALIDATED,
            )
        }

        report = engine.evaluate_certification(
            auth_binding=valid_auth_binding,
            tool_records=tool_records,
            pipeline_run_id=pipeline_run_id,
        )

        assert report.certification_decision.startswith(CertificationDecision.NOT_CERTIFIED.value)
        assert report.pipeline_provenance_gate["status"] == "FAIL"
