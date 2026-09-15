"""AihaX — Automated Finding Verifier Test Suite.

Validates the full Automated Finding Verification Gate:
- CWE defensible mapping
- Immutable blocked checks (BLOCKED_SCOPE, BLOCKED_AUTHORIZATION, etc.)
- Evidence completeness check (Proof K)
- Multi-dimensional confidence separation (Invariant 8)
- Vulnerability strategies (C001, C002, C006, C022, C067-C069)
- Verification error handling (Invariant 10)
- Machine-readable explanation serialization
"""

import json
import pytest
from unittest.mock import patch

from backend.models.database import (
    BountyEligibility,
    Finding,
    FindingDisposition,
)
from backend.services.automated_finding_verifier import (
    AutomatedFindingVerifier,
    VerificationExplanationDTO,
)


def make_dummy_finding(
    vuln_type: str = "C002_Missing_Security_Headers",
    title: str = "Security Finding",
    affected_url: str = "https://test.local/",
    proof_request: str = "GET / HTTP/1.1",
    proof_response: str = "HTTP/1.1 200 OK\r\n\r\nHello",
    finding_disposition: str = "INCONCLUSIVE",
    verification_status: str = "CANDIDATE",
    false_positive: bool = False,
    cwe_id: str = None,
) -> Finding:
    return Finding(
        id="find-unit-1",
        scan_id="scan-unit-1",
        agent_id=1,
        title=title,
        vuln_type=vuln_type,
        category="web",
        severity="medium",
        affected_url=affected_url,
        proof_request=proof_request,
        proof_response=proof_response,
        finding_disposition=finding_disposition,
        verification_status=verification_status,
        false_positive=false_positive,
        cwe_id=cwe_id,
        confidence=20,
    )


class TestCweAuditing:
    """Tests for audit_cwe_mapping."""

    def test_c047_csp_maps_to_cwe_693(self):
        assert AutomatedFindingVerifier.audit_cwe_mapping("C047_CSP", "CWE-1021") == "CWE-693"

    def test_c050_mime_maps_to_cwe_706(self):
        assert AutomatedFindingVerifier.audit_cwe_mapping("C050_MIME", "CWE-116") == "CWE-706"

    def test_c010_hsts_maps_to_cwe_319(self):
        assert AutomatedFindingVerifier.audit_cwe_mapping("C010_HSTS", None) == "CWE-319"

    def test_c049_clickjacking_maps_to_cwe_1021(self):
        assert AutomatedFindingVerifier.audit_cwe_mapping("C049_Clickjacking", None) == "CWE-1021"

    def test_c006_directory_listing_maps_to_cwe_548(self):
        assert AutomatedFindingVerifier.audit_cwe_mapping("C006_Directory_Listing", None) == "CWE-548"

    def test_c022_auth_rate_limit_maps_to_cwe_307(self):
        assert AutomatedFindingVerifier.audit_cwe_mapping("C022_Auth_Rate_Limit", None) == "CWE-307"

    def test_c002_headers_maps_to_cwe_693(self):
        assert AutomatedFindingVerifier.audit_cwe_mapping("C002_Missing_Headers", None) == "CWE-693"

    def test_c068_idor_maps_to_cwe_639(self):
        assert AutomatedFindingVerifier.audit_cwe_mapping("C068_IDOR_PROFILE", None) == "CWE-639"


class TestImmutableBlockedChecks:
    """Invariant 9: Blocked executions are immutable and cannot become VALIDATED."""

    def test_blocked_scope_cannot_validate(self):
        f = make_dummy_finding(finding_disposition="BLOCKED_SCOPE")
        res = AutomatedFindingVerifier.verify_finding(f)
        assert res.disposition == FindingDisposition.BLOCKED_SCOPE.value
        assert "AUTHORIZED_EXECUTION_REQUIRED" in res.failed_requirements
        assert f.finding_disposition == FindingDisposition.BLOCKED_SCOPE.value

    def test_blocked_authorization_cannot_validate(self):
        f = make_dummy_finding(finding_disposition="BLOCKED_AUTHORIZATION")
        res = AutomatedFindingVerifier.verify_finding(f)
        assert res.disposition == FindingDisposition.BLOCKED_AUTHORIZATION.value

    def test_blocked_safety_cannot_validate(self):
        f = make_dummy_finding(finding_disposition="BLOCKED_SAFETY")
        res = AutomatedFindingVerifier.verify_finding(f)
        assert res.disposition == FindingDisposition.BLOCKED_SAFETY.value

    def test_blocked_budget_cannot_validate(self):
        f = make_dummy_finding(finding_disposition="BLOCKED_BUDGET")
        res = AutomatedFindingVerifier.verify_finding(f)
        assert res.disposition == FindingDisposition.BLOCKED_BUDGET.value


class TestEvidenceCompletenessProofK:
    """Proof K: Missing evidence cannot validate, must become INCONCLUSIVE."""

    def test_missing_proof_response_yields_inconclusive(self):
        f = make_dummy_finding(proof_response="")
        res = AutomatedFindingVerifier.verify_finding(f, evidence_chain=[])
        assert res.disposition == FindingDisposition.INCONCLUSIVE.value
        assert "MISSING_PROOF_EVIDENCE" in res.failed_requirements
        assert f.finding_disposition == FindingDisposition.INCONCLUSIVE.value
        assert f.confidence <= 30

    def test_whitespace_only_proof_yields_inconclusive(self):
        f = make_dummy_finding(proof_response="   \n\t  ")
        res = AutomatedFindingVerifier.verify_finding(f, evidence_chain=[])
        assert res.disposition == FindingDisposition.INCONCLUSIVE.value
        assert "MISSING_PROOF_EVIDENCE" in res.failed_requirements


class TestVulnerabilityStrategies:
    """Tests for vulnerability-specific verification strategies."""

    def test_c001_redirect_to_https_is_false_positive(self):
        f = make_dummy_finding(
            vuln_type="C001_Open_Port_80",
            proof_response="HTTP/1.1 301 Moved\r\nLocation: https://example.com/\r\n\r\n",
        )
        res = AutomatedFindingVerifier.verify_finding(f)
        assert res.disposition == FindingDisposition.FALSE_POSITIVE.value
        assert f.finding_disposition == FindingDisposition.FALSE_POSITIVE.value

    def test_c001_no_redirect_is_hardening_only(self):
        f = make_dummy_finding(
            vuln_type="C001_Open_Port_80",
            proof_response="HTTP/1.1 200 OK\r\n\r\nUnencrypted website content",
        )
        res = AutomatedFindingVerifier.verify_finding(f)
        assert res.disposition == FindingDisposition.HARDENING_ONLY.value
        assert res.condition_confidence == 1.0
        assert res.impact_confidence == 0.0
        assert res.exploitability_confidence == 0.0
        assert f.verdict == "Hardening Only"
        assert f.confidence == 50

    def test_c002_security_headers_is_hardening_only(self):
        f = make_dummy_finding(
            vuln_type="C002_Missing_Security_Headers",
            proof_response="HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\nHome Page",
        )
        res = AutomatedFindingVerifier.verify_finding(f)
        assert res.disposition == FindingDisposition.HARDENING_ONLY.value
        assert res.condition_confidence == 1.0
        assert res.impact_confidence == 0.0
        assert f.confidence == 50
        assert res.bounty_eligibility == BountyEligibility.INELIGIBLE.value

    def test_c022_rate_limiting_without_bypass_is_inconclusive(self):
        f = make_dummy_finding(
            vuln_type="C022_Auth_Rate_Limit",
            proof_response="5 consecutive login attempts returned 200 OK (no 429 triggered)",
        )
        res = AutomatedFindingVerifier.verify_finding(f)
        assert res.disposition == FindingDisposition.INCONCLUSIVE.value
        assert res.impact_confidence == 0.0
        assert f.confidence <= 30

    def test_c022_rate_limiting_with_proven_bypass_is_validated(self):
        f = make_dummy_finding(
            vuln_type="C022_Auth_Rate_Limit",
            proof_response="bypass_demonstrated: automated_stuffing_confirmed after 20 attempts without throttle",
        )
        policy = {"name": "TestProg", "in_scope_vuln_types": ["C022_AUTH_RATE_LIMIT"]}
        res = AutomatedFindingVerifier.verify_finding(f, program_policy=policy)
        assert res.disposition == FindingDisposition.VALIDATED.value
        assert res.condition_confidence == 1.0
        assert res.impact_confidence >= 0.8
        assert f.confidence >= 70

    def test_c006_benign_directory_listing_is_hardening_only(self):
        f = make_dummy_finding(
            vuln_type="C006_Directory_Listing",
            proof_response="Index of /images/ \n logo.png \n icon.svg",
        )
        res = AutomatedFindingVerifier.verify_finding(f)
        assert res.disposition == FindingDisposition.HARDENING_ONLY.value
        assert res.impact_confidence == 0.0
        assert f.verdict == "Hardening Only"

    def test_c006_sensitive_directory_listing_is_validated(self):
        f = make_dummy_finding(
            vuln_type="C006_Directory_Listing",
            proof_response="Index of /backup/ \n database.sql \n .env \n id_rsa",
        )
        policy = {"name": "TestProg", "in_scope_vuln_types": ["C006_DIRECTORY_LISTING"]}
        res = AutomatedFindingVerifier.verify_finding(f, program_policy=policy)
        assert res.disposition == FindingDisposition.VALIDATED.value
        assert res.impact_confidence >= 0.8
        assert f.verdict == "Verified"


class TestMultiDimensionalConfidenceInvariants:
    """Invariant 8: Independent confidence dimensions must not collapse into high score."""

    def test_condition_1_impact_0_exploitability_0_capped(self):
        f = make_dummy_finding(vuln_type="C002_Missing_Security_Headers")
        res = AutomatedFindingVerifier.verify_finding(f)
        assert res.condition_confidence == 1.0
        assert res.impact_confidence == 0.0
        assert res.exploitability_confidence == 0.0
        assert f.confidence <= 50
        assert res.disposition != FindingDisposition.VALIDATED.value


class TestVerificationErrorHandling:
    """Invariant 10: Verifier internal failures must produce explicit VERIFICATION_ERROR."""

    def test_verification_engine_failure_produces_error_state(self):
        f = make_dummy_finding()
        with patch.object(AutomatedFindingVerifier, "_execute_verification", side_effect=RuntimeError("Database corruption simulation")):
            res = AutomatedFindingVerifier.verify_finding(f)
            assert res.disposition == FindingDisposition.VERIFICATION_ERROR.value
            assert "Database corruption simulation" in res.reason
            assert f.finding_disposition == FindingDisposition.VERIFICATION_ERROR.value
            assert f.verdict == "Verification Error"
            assert f.confidence == 0

    def test_verification_explanation_json_persisted(self):
        f = make_dummy_finding()
        res = AutomatedFindingVerifier.verify_finding(f)
        assert f.verification_explanation is not None
        parsed = json.loads(f.verification_explanation)
        assert parsed["disposition"] == res.disposition
        assert "verified_at" in parsed
        assert "strategy_version" in parsed
