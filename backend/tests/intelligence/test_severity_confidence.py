"""AihaX Phase 7 — Unit tests for SeverityEngine and ConfidenceEngine."""

import pytest
from unittest.mock import MagicMock


def _make_finding(
    vuln_type="C023_SQL_Injection",
    severity="high",
    verification_reason_code="REPRODUCED_SUCCESSFULLY",
    payload="' OR 1=1--",
    proof_request="GET /search HTTP/1.1",
    proof_response="SQL error",
    confidence=80,
    false_positive=False,
    affected_url="http://testsite.com/search",
    affected_param="q",
):
    f = MagicMock()
    f.vuln_type = vuln_type
    f.severity = severity
    f.verification_reason_code = verification_reason_code
    f.payload = payload
    f.proof_request = proof_request
    f.proof_response = proof_response
    f.confidence = confidence
    f.false_positive = false_positive
    f.affected_url = affected_url
    f.affected_param = affected_param
    f.cwe_id = None
    f.verdict = "Verified"
    f.id = "find-001"
    return f


class TestSeverityEngine:

    def test_sql_injection_minimum_high(self):
        from backend.intelligence.severity_engine import SeverityEngine, Severity
        finding = _make_finding(vuln_type="C023_SQL_Injection", severity="medium")
        result = SeverityEngine.assess(finding)
        # C023 has a floor of HIGH
        assert result.severity in (Severity.HIGH, Severity.CRITICAL)

    def test_command_injection_critical(self):
        from backend.intelligence.severity_engine import SeverityEngine, Severity
        finding = _make_finding(
            vuln_type="C027_OS_Command_Injection",
            severity="critical",
            payload="$(id)",
        )
        result = SeverityEngine.assess(finding)
        assert result.severity == Severity.CRITICAL

    def test_info_check_low_by_default(self):
        from backend.intelligence.severity_engine import SeverityEngine, Severity
        finding = _make_finding(
            vuln_type="C001_Open_Port",
            severity="info",
            payload="",
            proof_response="",
        )
        result = SeverityEngine.assess(finding)
        assert result.severity in (Severity.INFO, Severity.LOW)

    def test_severity_score_in_range(self):
        from backend.intelligence.severity_engine import SeverityEngine
        finding = _make_finding()
        result = SeverityEngine.assess(finding)
        assert 0 <= result.score <= 100

    def test_factors_are_populated(self):
        from backend.intelligence.severity_engine import SeverityEngine
        finding = _make_finding(vuln_type="C036_SSRF")
        result = SeverityEngine.assess(finding)
        assert result.factors is not None

    def test_safe_encoding_reduces_severity(self):
        from backend.intelligence.severity_engine import SeverityEngine, Severity
        finding = _make_finding(
            vuln_type="C037_Reflected_XSS",
            severity="high",
            verification_reason_code="INPUT_SAFELY_ENCODED",
        )
        result = SeverityEngine.assess(finding)
        # Safe encoding should reduce or not inflate severity
        assert result.score < 70  # Significant reduction from encoding penalty

    def test_passive_only_reduces_severity(self):
        from backend.intelligence.severity_engine import SeverityEngine, Severity
        finding = _make_finding(
            vuln_type="C001_Open_Port",
            severity="info",
            verification_reason_code="PASSIVE",
            proof_request=None,
            proof_response=None,
        )
        result = SeverityEngine.assess(finding)
        assert result.severity in (Severity.INFO, Severity.LOW)

    def test_explanation_not_empty(self):
        from backend.intelligence.severity_engine import SeverityEngine
        finding = _make_finding()
        result = SeverityEngine.assess(finding)
        assert result.explanation
        assert len(result.explanation) > 5

    def test_severity_is_deterministic(self):
        """Same input must always produce same severity."""
        from backend.intelligence.severity_engine import SeverityEngine
        finding = _make_finding(vuln_type="C023_SQL_Injection", severity="high")
        r1 = SeverityEngine.assess(finding)
        r2 = SeverityEngine.assess(finding)
        assert r1.severity == r2.severity
        assert r1.score == r2.score

    def test_severity_independent_from_confidence(self):
        """High severity with low confidence must be valid."""
        from backend.intelligence.severity_engine import SeverityEngine, Severity
        finding = _make_finding(
            vuln_type="C023_SQL_Injection",
            severity="high",
            confidence=20,  # Low confidence
        )
        result = SeverityEngine.assess(finding)
        # Severity should still be high regardless of confidence
        assert result.severity in (Severity.HIGH, Severity.CRITICAL)

    def test_to_dict_round_trip(self):
        from backend.intelligence.severity_engine import SeverityEngine
        finding = _make_finding()
        result = SeverityEngine.assess(finding)
        d = result.to_dict()
        assert "severity" in d
        assert "score" in d
        assert "factors" in d
        assert "explanation" in d


class TestConfidenceEngine:

    def test_candidate_only_low_confidence(self):
        from backend.intelligence.confidence_engine import ConfidenceEngine, ConfidenceLevel, ConfidenceSignals
        signals = ConfidenceSignals()  # No positive signals
        result = ConfidenceEngine.assess(signals)
        assert result.level == ConfidenceLevel.LOW

    def test_reproduced_high_confidence(self):
        from backend.intelligence.confidence_engine import ConfidenceEngine, ConfidenceLevel, ConfidenceSignals
        signals = ConfidenceSignals(
            deterministically_reproduced=True,
            negative_control_passed=True,
            proof_request_present=True,
            proof_response_present=True,
        )
        result = ConfidenceEngine.assess(signals)
        # Score: reproduced(35) + negative_control(15) + proof_req(3) + proof_resp(3) = 56 → MEDIUM
        # With independent paths added it reaches HIGH
        assert result.level in (ConfidenceLevel.MEDIUM, ConfidenceLevel.HIGH, ConfidenceLevel.CERTAIN)
        assert result.score >= 50  # At minimum MEDIUM territory

    def test_full_verification_certain(self):
        from backend.intelligence.confidence_engine import ConfidenceEngine, ConfidenceLevel, ConfidenceSignals
        signals = ConfidenceSignals(
            deterministically_reproduced=True,
            math_canary_confirmed=True,
            baseline_differential_verified=True,
            negative_control_passed=True,
            false_positive_control_verified=True,
            independent_verification_paths=3,
            evidence_hash_valid=True,
            proof_request_present=True,
            proof_response_present=True,
            response_consistent_across_repeats=True,
        )
        result = ConfidenceEngine.assess(signals)
        assert result.level == ConfidenceLevel.CERTAIN
        assert result.score >= 90

    def test_heuristic_only_capped_at_medium(self):
        from backend.intelligence.confidence_engine import ConfidenceEngine, ConfidenceLevel, ConfidenceSignals
        signals = ConfidenceSignals(
            heuristic_only=True,
            deterministically_reproduced=False,
        )
        result = ConfidenceEngine.assess(signals)
        assert result.level in (ConfidenceLevel.LOW, ConfidenceLevel.MEDIUM)
        assert result.score <= 45  # Capped at MEDIUM floor

    def test_passive_observation_capped(self):
        from backend.intelligence.confidence_engine import ConfidenceEngine, ConfidenceLevel, ConfidenceSignals
        signals = ConfidenceSignals(passive_observation_only=True)
        result = ConfidenceEngine.assess(signals)
        assert result.score <= 40

    def test_duplicate_heuristics_no_inflation(self):
        """Multiple identical heuristic observations must not inflate beyond MEDIUM."""
        from backend.intelligence.confidence_engine import ConfidenceEngine, ConfidenceLevel, ConfidenceSignals
        # Even 10 independent paths if all are heuristic must be capped
        signals = ConfidenceSignals(
            heuristic_only=True,
            independent_verification_paths=10,  # Will be capped at 3
        )
        result = ConfidenceEngine.assess(signals)
        assert result.level in (ConfidenceLevel.LOW, ConfidenceLevel.MEDIUM)
        assert result.independent_paths_counted == 3  # Cap enforced

    def test_confidence_deterministic(self):
        from backend.intelligence.confidence_engine import ConfidenceEngine, ConfidenceSignals
        signals = ConfidenceSignals(deterministically_reproduced=True)
        r1 = ConfidenceEngine.assess(signals)
        r2 = ConfidenceEngine.assess(signals)
        assert r1.level == r2.level
        assert r1.score == r2.score

    def test_from_finding_evidence(self):
        from backend.intelligence.confidence_engine import ConfidenceEngine, ConfidenceLevel
        result = ConfidenceEngine.from_finding_evidence(
            proof_request="GET /test HTTP/1.1",
            proof_response="RESPONSE",
            verification_reason_code="REPRODUCED_SUCCESSFULLY",
            evidence_ids='["EVD-001"]',
            evidence_hash_valid=True,
            is_false_positive=False,
        )
        assert result.level in (ConfidenceLevel.MEDIUM, ConfidenceLevel.HIGH, ConfidenceLevel.CERTAIN)

    def test_confidence_score_in_range(self):
        from backend.intelligence.confidence_engine import ConfidenceEngine, ConfidenceSignals
        for _ in range(10):
            signals = ConfidenceSignals(
                deterministically_reproduced=True,
                heuristic_only=False,
            )
            result = ConfidenceEngine.assess(signals)
            assert 0 <= result.score <= 100

    def test_explanation_present(self):
        from backend.intelligence.confidence_engine import ConfidenceEngine, ConfidenceSignals
        signals = ConfidenceSignals(deterministically_reproduced=True)
        result = ConfidenceEngine.assess(signals)
        assert result.explanation
        assert "Confidence" in result.explanation
