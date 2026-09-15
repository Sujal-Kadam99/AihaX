"""AihaX — Policy & Bug Bounty Eligibility Gate Test Suite.

Validates deterministic separation of technical vulnerability validity from bug-bounty eligibility,
standard exclusion enforcement, program policy rules, and the UNKNOWN policy invariant (Proof L).
"""

import pytest
from backend.models.database import BountyEligibility
from backend.services.policy_eligibility_gate import (
    PolicyEligibilityGate,
    PolicyEligibilityResult,
)


class TestStandardPolicyExclusions:
    """Tests for standard bug-bounty program exclusions."""

    def test_false_positives_strictly_ineligible(self):
        res = PolicyEligibilityGate.evaluate(
            vuln_type="C015_SQLI",
            finding_disposition="FALSE_POSITIVE",
            exploitability_confidence=0.0,
        )
        assert res.eligibility == BountyEligibility.INELIGIBLE.value
        assert res.policy_eligibility_confidence == 1.0

    def test_hardening_only_strictly_ineligible(self):
        res = PolicyEligibilityGate.evaluate(
            vuln_type="C002_SECURITY_HEADERS",
            finding_disposition="HARDENING_ONLY",
            exploitability_confidence=0.0,
        )
        assert res.eligibility == BountyEligibility.INELIGIBLE.value
        assert res.policy_eligibility_confidence == 1.0
        assert res.is_hardening_only

    def test_missing_csp_standard_exclusion(self):
        res = PolicyEligibilityGate.evaluate(
            vuln_type="C047_MISSING_CSP",
            finding_disposition="INCONCLUSIVE",
            exploitability_confidence=0.0,
        )
        assert res.eligibility == BountyEligibility.INELIGIBLE.value
        assert "CSP" in res.rationale

    def test_missing_xfo_standard_exclusion(self):
        res = PolicyEligibilityGate.evaluate(
            vuln_type="C049_CLICKJACKING",
            finding_disposition="INCONCLUSIVE",
            exploitability_confidence=0.0,
        )
        assert res.eligibility == BountyEligibility.INELIGIBLE.value
        assert "X-Frame-Options" in res.rationale

    def test_rate_limiting_without_takeover_excluded(self):
        res = PolicyEligibilityGate.evaluate(
            vuln_type="C022_AUTH_RATE_LIMIT",
            finding_disposition="INCONCLUSIVE",
            exploitability_confidence=0.0,
        )
        assert res.eligibility == BountyEligibility.INELIGIBLE.value
        assert "Missing rate limiting" in res.rationale

    def test_rate_limiting_with_proven_bypass_can_be_eligible(self):
        policy = {"name": "TestProgram", "in_scope_vuln_types": ["C022_AUTH_RATE_LIMIT"]}
        res = PolicyEligibilityGate.evaluate(
            vuln_type="C022_AUTH_RATE_LIMIT",
            finding_disposition="VALIDATED",
            exploitability_confidence=0.8,
            program_policy=policy,
        )
        assert res.eligibility == BountyEligibility.ELIGIBLE.value

    def test_dos_strictly_ineligible(self):
        res = PolicyEligibilityGate.evaluate(
            vuln_type="DOS_SLOWLORIS",
            finding_disposition="VALIDATED",
            exploitability_confidence=0.9,
        )
        assert res.eligibility == BountyEligibility.INELIGIBLE.value
        assert "Denial of Service" in res.rationale

    def test_self_xss_ineligible(self):
        res = PolicyEligibilityGate.evaluate(
            vuln_type="SELF_XSS_PROFILE",
            finding_disposition="VALIDATED",
            exploitability_confidence=0.5,
        )
        assert res.eligibility == BountyEligibility.INELIGIBLE.value
        assert "Self-XSS" in res.rationale

    def test_logout_csrf_ineligible(self):
        res = PolicyEligibilityGate.evaluate(
            vuln_type="LOGOUT_CSRF",
            finding_disposition="VALIDATED",
            exploitability_confidence=0.5,
        )
        assert res.eligibility == BountyEligibility.INELIGIBLE.value
        assert "Logout CSRF" in res.rationale


class TestCustomProgramPolicies:
    """Tests for custom program policy overrides."""

    def test_custom_policy_explicit_exclusion(self):
        policy = {
            "name": "AcmeBounty",
            "excluded_vuln_types": ["OPEN_REDIRECT", "INFO_LEAK"],
        }
        res = PolicyEligibilityGate.evaluate(
            vuln_type="OPEN_REDIRECT",
            finding_disposition="VALIDATED",
            exploitability_confidence=0.8,
            program_policy=policy,
        )
        assert res.eligibility == BountyEligibility.INELIGIBLE.value
        assert "explicitly excluded" in res.rationale

    def test_custom_policy_explicit_inclusion(self):
        policy = {
            "name": "AcmeBounty",
            "in_scope_vuln_types": ["IDOR", "RCE", "SQLI"],
        }
        res = PolicyEligibilityGate.evaluate(
            vuln_type="C068_IDOR",
            finding_disposition="VALIDATED",
            exploitability_confidence=0.8,
            program_policy=policy,
        )
        assert res.eligibility == BountyEligibility.ELIGIBLE.value
        assert res.policy_eligibility_confidence >= 0.85
        assert "explicitly eligible" in res.rationale


class TestPolicyUnknownInvariantProofL:
    """Proof L Invariant: Policy unknown CANNOT become automatically eligible."""

    def test_proof_l_high_impact_without_policy_remains_unknown(self):
        res = PolicyEligibilityGate.evaluate(
            vuln_type="C068_IDOR_ACCOUNT_TAKEOVER",
            finding_disposition="VALIDATED",
            exploitability_confidence=0.9,
            program_policy=None,  # Policy unavailable
        )
        assert res.eligibility == BountyEligibility.UNKNOWN.value
        assert res.policy_eligibility_confidence == 0.0
        assert "Eligibility remains UNKNOWN" in res.rationale

    def test_proof_l_sqli_without_policy_remains_unknown(self):
        res = PolicyEligibilityGate.evaluate(
            vuln_type="SQLI_BLIND_TIME",
            finding_disposition="VALIDATED",
            exploitability_confidence=0.95,
            program_policy=None,
        )
        assert res.eligibility == BountyEligibility.UNKNOWN.value
        assert res.policy_eligibility_confidence == 0.0

    def test_proof_l_generic_unknown_fallback(self):
        res = PolicyEligibilityGate.evaluate(
            vuln_type="UNUSUAL_CUSTOM_CHECK",
            finding_disposition="INCONCLUSIVE",
            exploitability_confidence=0.2,
            program_policy=None,
        )
        assert res.eligibility == BountyEligibility.UNKNOWN.value
        assert res.policy_eligibility_confidence == 0.0
