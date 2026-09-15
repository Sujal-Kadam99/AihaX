"""AihaX Phase 7 — Unit tests for FindingClassifier."""

import pytest
from unittest.mock import MagicMock


def _make_finding(
    vuln_type="C023_SQL_Injection",
    category="injection",
    affected_url="http://testsite.com/search",
    affected_param="q",
    verification_reason_code="REPRODUCED_SUCCESSFULLY",
    cwe_id="CWE-89",
    severity="high",
    verdict="Verified",
    payload="' OR 1=1--",
    proof_request="GET /search?q=' HTTP/1.1\nHost: testsite.com",
    proof_response="SQL syntax error near...",
    confidence=80,
    false_positive=False,
):
    f = MagicMock()
    f.vuln_type = vuln_type
    f.category = category
    f.affected_url = affected_url
    f.affected_param = affected_param
    f.verification_reason_code = verification_reason_code
    f.cwe_id = cwe_id
    f.severity = severity
    f.verdict = verdict
    f.payload = payload
    f.proof_request = proof_request
    f.proof_response = proof_response
    f.confidence = confidence
    f.false_positive = false_positive
    f.id = "find-001"
    f.evidence_ids = "[]"
    f.request_ids = "[]"
    f.verification_status = "REPORTABLE"
    f.verification_method = "Differential"
    f.business_impact = None
    f.remediation = None
    f.chain_id = None
    return f


class TestFindingClassifier:

    def test_basic_classification_sql(self):
        from backend.intelligence.finding_classifier import FindingClassifier
        finding = _make_finding()
        result = FindingClassifier.classify(finding)
        assert result.check_number == "C023"
        assert result.check_id == "C023_SQL_Injection"
        assert result.normalized_family == "injection"
        assert "Injection" in result.vulnerability_category or "injection" in result.vulnerability_category.lower()
        assert result.owasp_top10.startswith("A03")

    def test_xss_classification(self):
        from backend.intelligence.finding_classifier import FindingClassifier
        finding = _make_finding(vuln_type="C037_Reflected_XSS", category="xss", cwe_id="CWE-79")
        result = FindingClassifier.classify(finding)
        assert result.check_number == "C037"
        assert "xss" in result.normalized_family.lower()
        assert result.owasp_top10.startswith("A03")

    def test_idor_classification_requires_auth(self):
        from backend.intelligence.finding_classifier import FindingClassifier
        finding = _make_finding(vuln_type="C067_IDOR_Numeric", category="idor")
        result = FindingClassifier.classify(finding)
        assert result.check_number == "C067"
        assert result.requires_auth_proof is True

    def test_ssti_classification(self):
        from backend.intelligence.finding_classifier import FindingClassifier
        finding = _make_finding(vuln_type="C028_SSTI", category="ssti")
        result = FindingClassifier.classify(finding)
        assert result.check_number == "C028"
        assert result.normalized_family == "injection"

    def test_param_location_header(self):
        from backend.intelligence.finding_classifier import FindingClassifier
        finding = _make_finding(affected_param="header:Authorization")
        result = FindingClassifier.classify(finding)
        assert result.parameter_location == "http_header"

    def test_param_location_cookie(self):
        from backend.intelligence.finding_classifier import FindingClassifier
        finding = _make_finding(affected_param="cookie_session")
        result = FindingClassifier.classify(finding)
        assert result.parameter_location == "cookie"

    def test_check_id_preserved(self):
        """Original check ID must always be preserved."""
        from backend.intelligence.finding_classifier import FindingClassifier
        for check_id in ["C001_Open_Port", "C023_SQL_Injection", "C077_Missing_Reauth"]:
            finding = _make_finding(vuln_type=check_id)
            result = FindingClassifier.classify(finding)
            assert result.check_id == check_id

    def test_subcategory_extraction(self):
        from backend.intelligence.finding_classifier import FindingClassifier
        finding = _make_finding(vuln_type="C023_SQL_Injection")
        result = FindingClassifier.classify(finding)
        assert "Sql Injection" in result.subcategory or "SQL" in result.subcategory.upper()

    def test_to_dict_round_trip(self):
        from backend.intelligence.finding_classifier import FindingClassifier
        finding = _make_finding()
        result = FindingClassifier.classify(finding)
        d = result.to_dict()
        assert d["check_id"] == "C023_SQL_Injection"
        assert "owasp_top10" in d
        assert "attack_surface" in d

    def test_all_77_check_prefixes_classifiable(self):
        """All 77 check prefixes C001-C077 should produce valid classifications."""
        from backend.intelligence.finding_classifier import FindingClassifier
        for n in range(1, 78):
            check_id = f"C{n:03d}_Test_Check"
            finding = _make_finding(vuln_type=check_id, category="misconfiguration")
            result = FindingClassifier.classify(finding)
            assert result.check_number == f"C{n:03d}"
            assert result.owasp_top10  # Always has an OWASP category
