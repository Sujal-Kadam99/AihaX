"""AihaX — False Positive Gate Test Suite.

Validates deterministic false-positive detection rules across transport security,
missing headers, access control contradictions, and generic error pages.
"""

import pytest
from backend.services.false_positive_gate import (
    FalsePositiveGate,
    FalsePositiveEvaluationResult,
)
from unittest import mock


class TestTransportSecurityFalsePositives:
    """Tests for evaluate_transport_security."""

    def test_http_301_to_https_is_false_positive(self):
        resp = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/\r\n\r\n"
        res = FalsePositiveGate.evaluate_transport_security("GET / HTTP/1.1", resp)
        assert res.is_false_positive
        assert res.rule_triggered == "FP-RULE-TRANSPORT-REDIRECT"
        assert res.confidence_penalty == 1.0

    def test_http_302_to_https_is_false_positive(self):
        resp = "HTTP/1.1 302 Found\r\nLocation: https://example.com/login\r\n\r\n"
        res = FalsePositiveGate.evaluate_transport_security("GET / HTTP/1.1", resp)
        assert res.is_false_positive
        assert res.rule_triggered == "FP-RULE-TRANSPORT-REDIRECT"

    def test_http_308_permanent_redirect_to_https(self):
        resp = "HTTP/1.1 308 Permanent Redirect\r\nLocation: https://example.com/\r\n\r\n"
        res = FalsePositiveGate.evaluate_transport_security("GET / HTTP/1.1", resp)
        assert res.is_false_positive

    def test_http_200_without_redirect_not_false_positive(self):
        resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nPlain HTTP serving content"
        res = FalsePositiveGate.evaluate_transport_security("GET / HTTP/1.1", resp)
        assert not res.is_false_positive

    def test_redirect_to_cleartext_http_not_false_positive(self):
        resp = "HTTP/1.1 301 Moved Permanently\r\nLocation: http://other.example.com/\r\n\r\n"
        res = FalsePositiveGate.evaluate_transport_security("GET / HTTP/1.1", resp)
        assert not res.is_false_positive


class TestSecurityHeaderFalsePositives:
    """Tests for evaluate_security_headers."""

    def test_csp_header_present_is_false_positive(self):
        resp = "HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'self'\r\n\r\nOK"
        res = FalsePositiveGate.evaluate_security_headers("C047_Missing_CSP", resp)
        assert res.is_false_positive
        assert res.rule_triggered == "FP-RULE-HEADER-CSP-PRESENT"

    def test_csp_header_absent_not_false_positive(self):
        resp = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nOK"
        res = FalsePositiveGate.evaluate_security_headers("C047_Missing_CSP", resp)
        assert not res.is_false_positive

    def test_x_frame_options_present_is_false_positive(self):
        resp = "HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\n\r\nOK"
        res = FalsePositiveGate.evaluate_security_headers("C049_Clickjacking", resp)
        assert res.is_false_positive
        assert res.rule_triggered == "FP-RULE-HEADER-FRAME-PRESENT"

    def test_frame_ancestors_directive_present_is_false_positive(self):
        resp = "HTTP/1.1 200 OK\r\nContent-Security-Policy: frame-ancestors 'none'\r\n\r\nOK"
        res = FalsePositiveGate.evaluate_security_headers("C049_Clickjacking", resp)
        assert res.is_false_positive
        assert res.rule_triggered == "FP-RULE-HEADER-FRAME-PRESENT"

    def test_hsts_present_is_false_positive(self):
        resp = "HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\n\r\nOK"
        res = FalsePositiveGate.evaluate_security_headers("C010_HSTS", resp)
        assert res.is_false_positive
        assert res.rule_triggered == "FP-RULE-HEADER-HSTS-PRESENT"

    def test_hsts_absent_not_false_positive(self):
        resp = "HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\nOK"
        res = FalsePositiveGate.evaluate_security_headers("C010_HSTS", resp)
        assert not res.is_false_positive

    def test_nosniff_present_is_false_positive(self):
        resp = "HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\n\r\nOK"
        res = FalsePositiveGate.evaluate_security_headers("C050_MIME_Sniffing", resp)
        assert res.is_false_positive
        assert res.rule_triggered == "FP-RULE-HEADER-NOSNIFF-PRESENT"

    def test_nosniff_absent_not_false_positive(self):
        resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK"
        res = FalsePositiveGate.evaluate_security_headers("C050_MIME_Sniffing", resp)
        assert not res.is_false_positive


class TestAuthorizationEnforcementFalsePositives:
    """Tests for evaluate_authorization_enforcement."""

    def test_status_401_contradicts_auth_bypass(self):
        res = FalsePositiveGate.evaluate_authorization_enforcement(
            vuln_type="C067_AUTH_BYPASS",
            proof_response="HTTP/1.1 401 Unauthorized",
            status_code=401,
        )
        assert res.is_false_positive
        assert res.rule_triggered == "FP-RULE-AUTH-ENFORCED"

    def test_status_403_contradicts_idor(self):
        res = FalsePositiveGate.evaluate_authorization_enforcement(
            vuln_type="C068_IDOR",
            proof_response="HTTP/1.1 403 Forbidden\r\n\r\nAccess denied",
            status_code=403,
        )
        assert res.is_false_positive
        assert res.rule_triggered == "FP-RULE-AUTH-ENFORCED"

    def test_access_denied_body_contradicts_privilege_escalation(self):
        res = FalsePositiveGate.evaluate_authorization_enforcement(
            vuln_type="PRIVILEGE_ESCALATION",
            proof_response="HTTP/1.1 200 OK\r\n\r\n<html><body>Access Denied. Login required.</body></html>",
            status_code=200,
        )
        assert res.is_false_positive
        assert res.rule_triggered == "FP-RULE-AUTH-ENFORCED"

    def test_status_200_with_sensitive_content_not_false_positive(self):
        res = FalsePositiveGate.evaluate_authorization_enforcement(
            vuln_type="C068_IDOR",
            proof_response="HTTP/1.1 200 OK\r\n\r\n{\"user_id\": 10, \"secret_token\": \"admin_secret\"}",
            status_code=200,
        )
        assert not res.is_false_positive


class TestGenericErrorPageFalsePositives:
    """Tests for evaluate_framework_generic_error."""

    def test_standard_404_not_found_is_false_positive(self):
        resp = "HTTP/1.1 404 Not Found\r\n\r\n<center><h1>404 Not Found</h1></center><hr><center>nginx/1.18.0</center>"
        res = FalsePositiveGate.evaluate_framework_generic_error(
            vuln_type="C013_INFO_DISCLOSURE",
            proof_response=resp,
            status_code=404,
        )
        assert res.is_false_positive
        assert res.rule_triggered == "FP-RULE-GENERIC-ERROR-PAGE"

    def test_502_bad_gateway_is_false_positive(self):
        resp = "HTTP/1.1 502 Bad Gateway\r\n\r\n<html><head><title>502 Bad Gateway</title></head><body></body></html>"
        res = FalsePositiveGate.evaluate_framework_generic_error(
            vuln_type="C014_CONFIG_LEAK",
            proof_response=resp,
            status_code=502,
        )
        assert res.is_false_positive
        assert res.rule_triggered == "FP-RULE-GENERIC-ERROR-PAGE"

    def test_actual_sensitive_env_file_not_generic_error(self):
        resp = "HTTP/1.1 200 OK\r\n\r\nDB_PASSWORD=super_secret_123\nAWS_SECRET_KEY=AKIAIOSFODNN7"
        res = FalsePositiveGate.evaluate_framework_generic_error(
            vuln_type="C013_INFO_DISCLOSURE",
            proof_response=resp,
            status_code=200,
        )
        assert not res.is_false_positive


class TestCentralEvaluateOrchestrator:
    """Tests for FalsePositiveGate.evaluate."""

    def test_evaluate_transport_redirect(self):
        resp = "HTTP/1.1 301 Moved\r\nLocation: https://example.com/\r\n\r\n"
        res = FalsePositiveGate.evaluate(vuln_type="C001_OPEN_PORT", proof_response=resp)
        assert res.is_false_positive

    def test_evaluate_clean_finding_passes_all(self):
        resp = "HTTP/1.1 200 OK\r\n\r\n{\"profile\": \"unauthorized_data\"}"
        res = FalsePositiveGate.evaluate(vuln_type="C068_IDOR", proof_response=resp, status_code=200)
        assert not res.is_false_positive
        assert "Passed all" in res.reason

    @mock.patch("backend.core.chroma_client.query_similar")
    def test_evaluate_chromadb_historical_match(self, mock_query_similar):
        # Setup mock to return a close match
        mock_query_similar.return_value = [{"distance": 0.15, "document": "...", "metadata": {}}]
        
        req = "GET /test HTTP/1.1"
        resp = "HTTP/1.1 200 OK\r\n\r\nOK"
        res = FalsePositiveGate.evaluate(vuln_type="SQL_INJECTION", proof_request=req, proof_response=resp, status_code=200)
        
        # It shouldn't be a false positive outright
        assert not res.is_false_positive
        assert res.historical_fp_signal is True
        assert res.historical_fp_distance == 0.15
        assert res.confidence_penalty == 0.5
        assert "matches historical false-positive pattern" in res.reason
        assert any("Historical FP similarity match" in ev for ev in res.contradictory_evidence)
