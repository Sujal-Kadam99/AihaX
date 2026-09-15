"""AihaX — Reproducibility Evaluator Test Suite.

Validates deterministic reproduction, differential analysis, dual-identity IDOR verification,
and request consistency bounds without external network calls.
"""

import pytest
from backend.services.reproducibility_evaluator import (
    ReproducibilityEvaluator,
    ReproducibilityResultDTO,
)


class TestResponseConsistency:
    """Tests for evaluate_response_consistency."""

    def test_empty_responses_returns_zero(self):
        ok, score, rationale = ReproducibilityEvaluator.evaluate_response_consistency([])
        assert not ok
        assert score == 0.0
        assert "No response samples" in rationale

    def test_single_sample_baseline(self):
        samples = [{"status_code": 200, "body": "Normal response"}]
        ok, score, rationale = ReproducibilityEvaluator.evaluate_response_consistency(samples)
        assert ok
        assert score == 0.8
        assert "Single sample" in rationale

    def test_single_sample_expected_status_match(self):
        samples = [{"status_code": 200, "body": "OK"}]
        ok, score, _ = ReproducibilityEvaluator.evaluate_response_consistency(samples, expected_status=200)
        assert ok
        assert score == 0.8

    def test_single_sample_expected_status_mismatch(self):
        samples = [{"status_code": 500, "body": "Error"}]
        ok, score, rationale = ReproducibilityEvaluator.evaluate_response_consistency(samples, expected_status=200)
        assert not ok
        assert score == 0.0
        assert "does not match" in rationale

    def test_single_sample_pattern_match(self):
        samples = [{"status_code": 200, "body": "admin_portal_authenticated"}]
        ok, score, _ = ReproducibilityEvaluator.evaluate_response_consistency(samples, expected_body_pattern="admin_portal")
        assert ok
        assert score == 0.8

    def test_single_sample_pattern_mismatch(self):
        samples = [{"status_code": 200, "body": "guest_dashboard"}]
        ok, score, rationale = ReproducibilityEvaluator.evaluate_response_consistency(samples, expected_body_pattern="admin_portal")
        assert not ok
        assert score == 0.0
        assert "does not match expected pattern" in rationale

    def test_multiple_identical_responses_perfect_score(self):
        samples = [
            {"status_code": 200, "body": "Fixed payload reflection"},
            {"status_code": 200, "body": "Fixed payload reflection"},
            {"status_code": 200, "body": "Fixed payload reflection"},
        ]
        ok, score, rationale = ReproducibilityEvaluator.evaluate_response_consistency(samples)
        assert ok
        assert score == 1.0
        assert "Deterministic" in rationale

    def test_multiple_inconsistent_status_codes_penalized(self):
        samples = [
            {"status_code": 200, "body": "OK"},
            {"status_code": 500, "body": "Internal Server Error"},
            {"status_code": 200, "body": "OK"},
        ]
        ok, score, rationale = ReproducibilityEvaluator.evaluate_response_consistency(samples)
        assert not ok
        assert score == 0.3
        assert "Inconsistent status codes" in rationale

    def test_multiple_samples_slight_variance_high_score(self):
        # E.g. dynamic timestamps altering body length by 2%
        base = "A" * 1000
        samples = [
            {"status_code": 200, "body": base + "12:00:01"},
            {"status_code": 200, "body": base + "12:00:02"},
            {"status_code": 200, "body": base + "12:00:03"},
        ]
        ok, score, rationale = ReproducibilityEvaluator.evaluate_response_consistency(samples)
        assert ok
        assert score == 0.9
        assert "High consistency" in rationale

    def test_multiple_samples_large_variance_moderate_score(self):
        samples = [
            {"status_code": 200, "body": "Short"},
            {"status_code": 200, "body": "Much longer content body from unexpected server state"},
        ]
        ok, score, rationale = ReproducibilityEvaluator.evaluate_response_consistency(samples)
        assert ok
        assert score == 0.7
        assert "Consistent status code" in rationale


class TestDifferentialComparison:
    """Tests for evaluate_differential."""

    def test_missing_baseline_or_test_returns_zero(self):
        ok, score, rationale = ReproducibilityEvaluator.evaluate_differential({}, {})
        assert not ok
        assert score == 0.0
        assert "Missing baseline" in rationale

    def test_identical_responses_yield_zero_differential(self):
        base = {"status_code": 200, "body": "Welcome to our portal"}
        test = {"status_code": 200, "body": "Welcome to our portal"}
        ok, score, rationale = ReproducibilityEvaluator.evaluate_differential(base, test)
        assert not ok
        assert score == 0.0
        assert "zero differential" in rationale

    def test_status_code_transition_yields_differential(self):
        base = {"status_code": 200, "body": "Normal page"}
        test = {"status_code": 500, "body": "SQL syntax error"}
        ok, score, rationale = ReproducibilityEvaluator.evaluate_differential(base, test)
        assert ok
        assert score >= 0.7
        assert "Status transition" in rationale

    def test_body_divergence_yields_differential(self):
        base = {"status_code": 200, "body": "Normal page"}
        test = {"status_code": 200, "body": "Normal page with injected probe result"}
        ok, score, rationale = ReproducibilityEvaluator.evaluate_differential(base, test)
        assert ok
        assert score >= 0.7
        assert "content diverged" in rationale

    def test_differential_with_inverted_control(self):
        base = {"status_code": 200, "body": "Normal"}
        test = {"status_code": 500, "body": "Crash"}
        inv = {"status_code": 200, "body": "Normal"}
        ok, score, rationale = ReproducibilityEvaluator.evaluate_differential(base, test, inverted_response=inv)
        assert ok
        assert score >= 0.8
        assert "Inverted control probe confirmed" in rationale


class TestDualIdentityAccess:
    """Tests for evaluate_dual_identity_access (IDOR/BOLA)."""

    def test_missing_accounts_returns_zero(self):
        ok, score, rationale = ReproducibilityEvaluator.evaluate_dual_identity_access({}, {})
        assert not ok
        assert score == 0.0
        assert "Missing dual-identity" in rationale

    def test_session_contamination_identical_tokens_rejected(self):
        a = {"status_code": 200, "auth_token": "TOKEN_SHARED", "body": "data"}
        b = {"status_code": 200, "auth_token": "TOKEN_SHARED", "body": "data"}
        ok, score, rationale = ReproducibilityEvaluator.evaluate_dual_identity_access(a, b)
        assert not ok
        assert score == 0.0
        assert "identical authorization tokens" in rationale

    def test_access_denied_to_account_b_passes_enforcement(self):
        a = {"status_code": 200, "auth_token": "TOKEN_USER_A", "body": "account_a_private_profile"}
        b = {"status_code": 403, "auth_token": "TOKEN_USER_B", "body": "Forbidden"}
        ok, score, rationale = ReproducibilityEvaluator.evaluate_dual_identity_access(a, b)
        assert not ok
        assert score == 0.0
        assert "Access control enforced" in rationale

    def test_access_denied_via_401(self):
        a = {"status_code": 200, "auth_token": "TOKEN_USER_A", "body": "secret_doc"}
        b = {"status_code": 401, "auth_token": "TOKEN_USER_B", "body": "Unauthorized"}
        ok, score, rationale = ReproducibilityEvaluator.evaluate_dual_identity_access(a, b)
        assert not ok
        assert score == 0.0
        assert "Access control enforced" in rationale

    def test_confirmed_idor_account_b_receives_resource_of_a(self):
        res_id = "DOC-99881"
        a = {"status_code": 200, "auth_token": "TOKEN_A", "body": f"Ownership of {res_id} belongs to A"}
        b = {"status_code": 200, "auth_token": "TOKEN_B", "body": f"Ownership of {res_id} belongs to A"}
        ok, score, rationale = ReproducibilityEvaluator.evaluate_dual_identity_access(a, b, target_resource_id=res_id)
        assert ok
        assert score >= 0.9
        assert "Confirmed IDOR" in rationale

    def test_account_b_200_without_target_resource_inconclusive(self):
        res_id = "DOC-SECRET-99"
        a = {"status_code": 200, "auth_token": "TOKEN_A", "body": f"File {res_id}"}
        b = {"status_code": 200, "auth_token": "TOKEN_B", "body": "Standard dashboard"}
        ok, score, rationale = ReproducibilityEvaluator.evaluate_dual_identity_access(a, b, target_resource_id=res_id)
        assert not ok
        assert score <= 0.3
        assert "does not contain target resource" in rationale


class TestCentralEvaluate:
    """Tests for ReproducibilityEvaluator.evaluate orchestrator."""

    def test_evaluate_empty_chain(self):
        res = ReproducibilityEvaluator.evaluate(evidence_chain=[], vuln_type="SQLI")
        assert not res.is_reproduced
        assert res.reproducibility_score == 0.0
        assert not res.preconditions_met

    def test_evaluate_idor_without_dual_identity_evidence_fails(self):
        chain = [{"evidence_id": "EVD-1", "status_code": 200, "body": "data"}]
        res = ReproducibilityEvaluator.evaluate(evidence_chain=chain, vuln_type="C067_IDOR_PROFILE")
        assert not res.is_reproduced
        assert "dual-identity evidence" in res.rationale.lower()

    def test_evaluate_idor_with_dual_identity_confirmed(self):
        chain = [{"evidence_id": "EVD-1", "status_code": 200, "body": "data"}]
        dual_id = {
            "account_a": {"status_code": 200, "auth_token": "TK_A", "body": "secret_data_RES_123"},
            "account_b": {"status_code": 200, "auth_token": "TK_B", "body": "secret_data_RES_123"},
            "target_resource_id": "RES_123",
        }
        res = ReproducibilityEvaluator.evaluate(
            evidence_chain=chain,
            vuln_type="C068_BOLA_API",
            dual_identity_evidence=dual_id,
        )
        assert res.is_reproduced
        assert res.reproducibility_score >= 0.9
        assert "Confirmed IDOR" in res.rationale

    def test_evaluate_general_vuln_with_baseline(self):
        base = {"status_code": 200, "body": "Default"}
        chain = [
            {"evidence_id": "EVD-1", "status_code": 500, "body": "SQL syntax error near SELECT"},
            {"evidence_id": "EVD-2", "status_code": 500, "body": "SQL syntax error near SELECT"},
        ]
        res = ReproducibilityEvaluator.evaluate(
            evidence_chain=chain,
            vuln_type="C015_SQL_INJECTION",
            baseline_evidence=base,
        )
        assert res.is_reproduced
        assert res.reproducibility_score >= 0.8
        assert "Differential:" in res.rationale
