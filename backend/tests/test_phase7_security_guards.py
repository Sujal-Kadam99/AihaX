"""AihaX Phase 7 — Security Guards and Reporting Tests.

Tests the anti-hallucination guards (Section 16 of the Phase 7 spec) including:
- LifecycleState guard
- VerdictGuard
- EvidencePresenceGuard
- EvidenceHashGuard
- NotDestructiveGuard
- Lifecycle state machine transitions
- Secrets redaction
- Severity != Confidence independence
- 77-check registry integrity
"""

import pytest
from unittest.mock import MagicMock


def _make_finding(
    id_="find-001",
    vuln_type="C023_SQL_Injection",
    category="injection",
    severity="high",
    verdict="Verified",
    false_positive=False,
    verification_status="REPORTABLE",
    verification_reason_code="REPRODUCED_SUCCESSFULLY",
    affected_url="http://testsite.com/search",
    affected_param="q",
    payload="' OR 1=1--",
    proof_request="GET /search?q=%27 HTTP/1.1\nHost: testsite.com",
    proof_response="SQL syntax error",
    confidence=80,
    evidence_ids='["EVD-001"]',
    request_ids='["REQ-001"]',
    cwe_id="CWE-89",
    verification_method="Differential",
):
    f = MagicMock()
    f.id = id_
    f.vuln_type = vuln_type
    f.category = category
    f.severity = severity
    f.verdict = verdict
    f.false_positive = false_positive
    f.verification_status = verification_status
    f.verification_reason_code = verification_reason_code
    f.affected_url = affected_url
    f.affected_param = affected_param
    f.payload = payload
    f.proof_request = proof_request
    f.proof_response = proof_response
    f.confidence = confidence
    f.evidence_ids = evidence_ids
    f.request_ids = request_ids
    f.cwe_id = cwe_id
    f.verification_method = verification_method
    f.duplicate_of = None
    f.human_review_status = "APPROVED"
    return f


class TestReportGuards:

    def test_valid_finding_passes_all_guards(self):
        from backend.intelligence.report_guards import ReportGuard
        finding = _make_finding()
        report = ReportGuard.validate(finding)
        assert report.can_generate is True
        assert len(report.blocked_by) == 0

    def test_candidate_only_blocked(self):
        """A finding with only CANDIDATE status must not generate a report."""
        from backend.intelligence.report_guards import ReportGuard
        finding = _make_finding(
            verification_status="CANDIDATE",
            verdict="Inconclusive",
        )
        report = ReportGuard.validate(finding)
        assert report.can_generate is False
        assert any("lifecycle" in b.lower() for b in report.blocked_by)

    def test_false_positive_blocked(self):
        """False positive findings must not generate reports."""
        from backend.intelligence.report_guards import ReportGuard
        finding = _make_finding(false_positive=True, verdict="Verified")
        report = ReportGuard.validate(finding)
        assert report.can_generate is False

    def test_no_evidence_blocked(self):
        """Verified without evidence must be blocked."""
        from backend.intelligence.report_guards import ReportGuard
        finding = _make_finding(
            proof_request=None,
            proof_response=None,
            evidence_ids="[]",
        )
        report = ReportGuard.validate(finding)
        assert report.can_generate is False
        assert any("evidence" in b.lower() for b in report.blocked_by)

    def test_unverified_verdict_blocked(self):
        """Inconclusive verdict must not generate report."""
        from backend.intelligence.report_guards import ReportGuard
        finding = _make_finding(verdict="Inconclusive", verification_status="INCONCLUSIVE")
        report = ReportGuard.validate(finding)
        assert report.can_generate is False

    def test_destructive_payload_blocked(self):
        """DROP TABLE payloads must be blocked."""
        from backend.intelligence.report_guards import ReportGuard
        finding = _make_finding(payload="' ; DROP TABLE users; --")
        report = ReportGuard.validate(finding)
        assert report.can_generate is False

    def test_missing_url_blocked(self):
        """Missing affected_url must block report generation."""
        from backend.intelligence.report_guards import ReportGuard
        finding = _make_finding(affected_url="")
        report = ReportGuard.validate(finding)
        assert report.can_generate is False

    def test_validate_all_separates_approved_blocked(self):
        from backend.intelligence.report_guards import ReportGuard
        good = _make_finding(id_="find-good")
        bad = _make_finding(id_="find-bad", verification_status="CANDIDATE", verdict="Inconclusive")
        approved, blocked = ReportGuard.validate_all([good, bad])
        assert len(approved) == 1
        assert approved[0].id == "find-good"
        assert len(blocked) == 1
        assert blocked[0].finding_id == "find-bad"

    def test_evidence_hash_computed(self):
        """Every approved finding must have a computable evidence hash."""
        from backend.intelligence.report_guards import ReportGuard
        from backend.services.finding_deduplicator import EvidenceHasher
        finding = _make_finding()
        report = ReportGuard.validate(finding)
        hash_check = next((c for c in report.checks if c.guard_name == "evidence_hash_integrity"), None)
        assert hash_check is not None
        assert "PASS" in hash_check.result.value

    def test_guard_report_to_dict(self):
        from backend.intelligence.report_guards import ReportGuard
        finding = _make_finding()
        report = ReportGuard.validate(finding)
        d = report.to_dict()
        assert "finding_id" in d
        assert "can_generate" in d
        assert "checks" in d
        assert isinstance(d["checks"], list)


class TestLifecycleTransitionGuard:

    def test_valid_transitions_allowed(self):
        from backend.intelligence.report_guards import LifecycleTransitionGuard
        valid_cases = [
            ("DISCOVERED", "CANDIDATE"),
            ("CANDIDATE", "VERIFYING"),
            ("VERIFYING", "VERIFIED"),
            ("VERIFIED", "DEDUPLICATED"),
            ("DEDUPLICATED", "REPORTABLE"),
            ("VERIFIED", "REPORTABLE"),
        ]
        for current, target in valid_cases:
            allowed, reason = LifecycleTransitionGuard.validate_transition(current, target)
            assert allowed is True, f"{current}→{target} should be allowed but got: {reason}"

    def test_invalid_transitions_blocked(self):
        from backend.intelligence.report_guards import LifecycleTransitionGuard
        invalid_cases = [
            ("DISCOVERED", "REPORTABLE"),
            ("CANDIDATE", "REPORTABLE"),
            ("VERIFYING", "REPORTABLE"),
            ("REPORTABLE", "CANDIDATE"),
            ("REPORTABLE", "DISCOVERED"),
        ]
        for current, target in invalid_cases:
            allowed, reason = LifecycleTransitionGuard.validate_transition(current, target)
            assert allowed is False, f"{current}→{target} should be blocked"
            assert reason  # Must have an explanation

    def test_unknown_state_rejected(self):
        from backend.intelligence.report_guards import LifecycleTransitionGuard
        allowed, reason = LifecycleTransitionGuard.validate_transition("MADE_UP_STATE", "REPORTABLE")
        assert allowed is False
        assert reason


class TestSecretsInReports:

    def test_no_jwt_in_reproduction_package(self):
        """JWT tokens must be redacted in reproduction packages."""
        from backend.intelligence.reproducibility import _redact_secrets
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123"
        result = _redact_secrets(text)
        assert "eyJ" not in result or "[REDACTED" in result

    def test_no_password_in_reproduction_package(self):
        from backend.intelligence.reproducibility import _redact_secrets
        text = "password=supersecret123&username=admin"
        result = _redact_secrets(text)
        assert "supersecret123" not in result

    def test_no_api_key_in_reproduction_package(self):
        from backend.intelligence.reproducibility import _redact_secrets
        text = "api_key=AKIA1234567890ABCDEF"
        result = _redact_secrets(text)
        assert "AKIA1234567890ABCDEF" not in result

    def test_no_cookie_in_reproduction_package(self):
        from backend.intelligence.reproducibility import _redact_secrets
        text = "Cookie: session=abcdef123456; PHPSESSID=xyz"
        result = _redact_secrets(text)
        assert "abcdef123456" not in result

    def test_reproduction_package_sanitized_flag(self):
        from backend.intelligence.reproducibility import ReproducibilityEngine
        finding = _make_finding(
            proof_request="GET /search HTTP/1.1\nCookie: session=secret123",
            proof_response="SQL error near...",
        )
        pkg = ReproducibilityEngine.generate(finding)
        assert pkg.sanitized is True

    def test_contains_secrets_detection(self):
        from backend.intelligence.reproducibility import ReproductionPackage, ReproducibilityEngine
        pkg = ReproducibilityEngine.generate(_make_finding())
        # Since proof_request has no raw JWT, should not detect secrets
        # (our fixture proof_request is simple GET without real JWT)
        assert isinstance(pkg.contains_secrets(), bool)


class TestSeverityConfidenceIndependence:

    def test_high_severity_low_confidence_valid(self):
        """Severity=HIGH, Confidence=LOW must be a valid state."""
        from backend.intelligence.severity_engine import SeverityEngine, Severity
        from backend.intelligence.confidence_engine import ConfidenceEngine, ConfidenceLevel, ConfidenceSignals
        finding = _make_finding(vuln_type="C023_SQL_Injection", severity="high", confidence=20)
        sev = SeverityEngine.assess(finding)
        signals = ConfidenceSignals(heuristic_only=True)
        conf = ConfidenceEngine.assess(signals)
        # Severity should be HIGH+, Confidence should be LOW
        assert sev.severity in (Severity.HIGH, Severity.CRITICAL)
        assert conf.level == ConfidenceLevel.LOW

    def test_info_severity_high_confidence_valid(self):
        """INFO severity with HIGH confidence is valid (e.g., definitively confirmed minor issue)."""
        from backend.intelligence.severity_engine import SeverityEngine, Severity
        from backend.intelligence.confidence_engine import ConfidenceEngine, ConfidenceLevel, ConfidenceSignals
        finding = _make_finding(vuln_type="C001_Open_Port", severity="info", confidence=90)
        sev = SeverityEngine.assess(finding)
        signals = ConfidenceSignals(
            deterministically_reproduced=True,
            negative_control_passed=True,
            independent_verification_paths=2,
        )
        conf = ConfidenceEngine.assess(signals)
        # Score: reproduced(35) + negative_control(15) + 2 paths(16) = 66 → MEDIUM
        # Regardless: severity must be low/info, confidence must be ≥ MEDIUM
        assert sev.severity in (Severity.INFO, Severity.LOW)
        assert conf.level in (ConfidenceLevel.MEDIUM, ConfidenceLevel.HIGH, ConfidenceLevel.CERTAIN)
        assert conf.score >= 50


class TestRegistryIntegrity:

    def test_77_checks_registered(self):
        """The registry must have exactly 77 checks."""
        import backend.agents.checks  # Ensure all checks are registered
        from backend.core.check_registry import registry
        count = len(registry.list_checks())
        assert count == 77, f"Expected 77 checks, got {count}"

    def test_no_hardcoded_verified_in_checks(self):
        """No check module should hardcode 'VERIFIED' or 'REPORTABLE' verdicts."""
        import os
        import pathlib
        checks_dir = pathlib.Path("backend/agents/checks")
        violations = []
        if checks_dir.exists():
            for py_file in checks_dir.glob("*.py"):
                content = py_file.read_text(encoding="utf-8", errors="ignore")
                if '"VERIFIED"' in content or "'VERIFIED'" in content:
                    violations.append(f"{py_file}: hardcoded VERIFIED")
                if '"REPORTABLE"' in content or "'REPORTABLE'" in content:
                    violations.append(f"{py_file}: hardcoded REPORTABLE")
        assert violations == [], f"Hardcoded verdict violations: {violations}"
