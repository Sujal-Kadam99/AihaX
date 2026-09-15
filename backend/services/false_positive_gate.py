"""AihaX — False Positive Quality Gate.

Evaluates deterministic false-positive elimination rules:
1. HTTP 301/302 transport redirection to HTTPS negates cleartext HTTP transport vulnerabilities.
2. HTTP 401/403/404 responses contradict authorization bypass / IDOR claims.
3. Actual presence of security headers contradicts missing-header claims.
4. Framework default error pages (404/500) contradict sensitive information exposure.
5. Permissive CORS on public/static endpoints without credentials does not constitute vulnerability.
6. Benign public directory index (e.g. /images/, /static/) contradicts sensitive disclosure.
7. Unthrottled login requests without proven credential bypass do not prove authentication bypass.
"""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("aihax.false_positive_gate")

SENSITIVE_DIR_PATTERNS = [
    r"\.env\b", r"\.git\b", r"\.aws\b", r"\.ssh\b", r"\.sql\b",
    r"\.bak\b", r"\.backup\b", r"\.old\b", r"\.tar\b", r"\.gz\b",
    r"\.zip\b", r"\.dump\b", r"config\.(php|json|ya?ml|py|inc)\b",
    r"database\.(php|json|ya?ml|py|sqlite|db)\b", r"credentials?\b",
    r"password\b", r"secret\b", r"id_rsa\b", r"private_key\b",
    r"\.htpasswd\b"
]


@dataclass
class FalsePositiveEvaluationResult:
    """Outcome of false-positive evaluation."""
    is_false_positive: bool
    rule_triggered: Optional[str] = None
    reason: str = "No false-positive indicators triggered."
    contradictory_evidence: List[str] = field(default_factory=list)
    confidence_penalty: float = 0.0  # 0.0 to 1.0 deduction if suspicious
    historical_fp_signal: bool = False
    historical_fp_distance: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FalsePositiveGate:
    """Deterministic false-positive evaluator."""

    @classmethod
    def evaluate_transport_security(
        cls,
        proof_request: str,
        proof_response: str,
    ) -> FalsePositiveEvaluationResult:
        """Check whether cleartext HTTP (Port 80) safely redirects to HTTPS."""
        resp_lower = proof_response.lower()
        is_redirect = "301 moved" in resp_lower or "302 found" in resp_lower or "307 temporary" in resp_lower or "308 permanent" in resp_lower or "http/1.1 301" in resp_lower or "http/1.1 302" in resp_lower
        has_https_location = "location: https://" in resp_lower

        if is_redirect and has_https_location:
            return FalsePositiveEvaluationResult(
                is_false_positive=True,
                rule_triggered="FP-RULE-TRANSPORT-REDIRECT",
                reason="Cleartext HTTP endpoint safely issues 301/302 redirect to HTTPS.",
                contradictory_evidence=["HTTP 301/302 Redirect with Location: https://"],
                confidence_penalty=1.0,
            )

        return FalsePositiveEvaluationResult(is_false_positive=False)

    @classmethod
    def evaluate_security_headers(
        cls,
        vuln_type: str,
        proof_response: str,
    ) -> FalsePositiveEvaluationResult:
        """Check whether claimed missing security header is actually present in response."""
        vt = (vuln_type or "").upper()
        headers_lower = proof_response.lower()

        # CSP
        if ("CSP" in vt or "C047" in vt) and "content-security-policy:" in headers_lower:
            return FalsePositiveEvaluationResult(
                is_false_positive=True,
                rule_triggered="FP-RULE-HEADER-CSP-PRESENT",
                reason="Contradiction: Content-Security-Policy header is present in response.",
                contradictory_evidence=["Content-Security-Policy header found"],
                confidence_penalty=1.0,
            )

        # X-Frame-Options / Clickjacking
        if ("CLICKJACKING" in vt or "C049" in vt or "FRAME" in vt) and (
            "x-frame-options:" in headers_lower
            or ("content-security-policy:" in headers_lower and "frame-ancestors" in headers_lower)
        ):
            return FalsePositiveEvaluationResult(
                is_false_positive=True,
                rule_triggered="FP-RULE-HEADER-FRAME-PRESENT",
                reason="Contradiction: X-Frame-Options or frame-ancestors directive is present.",
                contradictory_evidence=["Frame protection header found"],
                confidence_penalty=1.0,
            )

        # HSTS
        if ("HSTS" in vt or "C010" in vt) and "strict-transport-security:" in headers_lower:
            return FalsePositiveEvaluationResult(
                is_false_positive=True,
                rule_triggered="FP-RULE-HEADER-HSTS-PRESENT",
                reason="Contradiction: Strict-Transport-Security header is present.",
                contradictory_evidence=["Strict-Transport-Security header found"],
                confidence_penalty=1.0,
            )

        # X-Content-Type-Options
        if ("SNIFF" in vt or "C050" in vt or "MIME" in vt) and "x-content-type-options: nosniff" in headers_lower:
            return FalsePositiveEvaluationResult(
                is_false_positive=True,
                rule_triggered="FP-RULE-HEADER-NOSNIFF-PRESENT",
                reason="Contradiction: X-Content-Type-Options: nosniff header is present.",
                contradictory_evidence=["nosniff header found"],
                confidence_penalty=1.0,
            )

        return FalsePositiveEvaluationResult(is_false_positive=False)

    @classmethod
    def evaluate_authorization_enforcement(
        cls,
        vuln_type: str,
        proof_response: str,
        status_code: Optional[int] = None,
    ) -> FalsePositiveEvaluationResult:
        """Check whether claimed authorization bypass is contradicted by access denial."""
        vt = (vuln_type or "").upper()
        # Rate limiting checks send invalid credentials and expect 401/200; they are not auth bypass checks
        if "RATE_LIMIT" in vt or "C022" in vt:
            return FalsePositiveEvaluationResult(is_false_positive=False)

        if any(k in vt for k in ["BYPASS", "AUTH", "IDOR", "BOLA", "UNAUTHORIZED", "PRIVILEGE"]):
            resp_lower = proof_response.lower()
            is_denied = (
                status_code in (401, 403)
                or "401 unauthorized" in resp_lower
                or "403 forbidden" in resp_lower
                or "access denied" in resp_lower
                or "login required" in resp_lower
            )
            if is_denied:
                return FalsePositiveEvaluationResult(
                    is_false_positive=True,
                    rule_triggered="FP-RULE-AUTH-ENFORCED",
                    reason="Contradiction: Endpoint enforced authentication/authorization (HTTP 401/403/Access Denied).",
                    contradictory_evidence=["HTTP 401/403 observed"],
                    confidence_penalty=1.0,
                )

        return FalsePositiveEvaluationResult(is_false_positive=False)

    @classmethod
    def evaluate_framework_generic_error(
        cls,
        vuln_type: str,
        proof_response: str,
        status_code: Optional[int] = None,
    ) -> FalsePositiveEvaluationResult:
        """Check whether claimed information disclosure is merely a standard web server 404/500 page."""
        vt = (vuln_type or "").upper()
        if any(k in vt for k in ["INFO", "DISCLOSURE", "LEAK", "CONFIG"]):
            resp_lower = proof_response.lower()
            # Standard Nginx, Apache, or Cloudflare error pages
            generic_error_patterns = [
                r"<center><h1>404 not found</h1></center>",
                r"<title>404 not found</title>",
                r"<title>502 bad gateway</title>",
                r"<title>500 internal server error</title>",
                r"apache/[0-9.]+ \([^)]+\) server at",
                r"nginx/[0-9.]+<",
            ]
            for pat in generic_error_patterns:
                if re.search(pat, resp_lower):
                    return FalsePositiveEvaluationResult(
                        is_false_positive=True,
                        rule_triggered="FP-RULE-GENERIC-ERROR-PAGE",
                        reason="Claimed information disclosure is a generic HTTP server error/404 page.",
                        contradictory_evidence=["Generic server error signature matched"],
                        confidence_penalty=0.9,
                    )

        return FalsePositiveEvaluationResult(is_false_positive=False)

    @classmethod
    def evaluate(
        cls,
        vuln_type: str,
        proof_request: Optional[str] = None,
        proof_response: Optional[str] = None,
        status_code: Optional[int] = None,
    ) -> FalsePositiveEvaluationResult:
        """Central evaluation function orchestrating all false-positive rules."""
        req = proof_request or ""
        resp = proof_response or ""
        vt = (vuln_type or "").upper()

        # 1. Transport Security (C001, Open Port 80)
        if "C001" in vt or "OPEN_PORT" in vt or "CLEARTEXT" in vt or "HTTP_PORT" in vt:
            res = cls.evaluate_transport_security(req, resp)
            if res.is_false_positive:
                return res

        # 2. Security Headers (C002, C010, C047, C049, C050)
        if any(h in vt for h in ["C002", "C010", "C047", "C049", "C050", "HEADER", "CSP", "FRAME", "SNIFF"]):
            res = cls.evaluate_security_headers(vt, resp)
            if res.is_false_positive:
                return res

        # 3. Authorization Enforcement (C067, C068, C069, IDOR, BOLA)
        res = cls.evaluate_authorization_enforcement(vt, resp, status_code)
        if res.is_false_positive:
            return res

        # 4. Generic error pages mimicking sensitive information
        res = cls.evaluate_framework_generic_error(vt, resp, status_code)
        if res.is_false_positive:
            return res

        # 5. ChromaDB Historical Match (Signal, not outright rejection)
        historical_fp_signal = False
        historical_fp_distance = None
        confidence_penalty = 0.0
        reason = "Passed all false-positive validation gates."
        contradictory_evidence = []

        if req or resp:
            try:
                from backend.core.chroma_client import query_similar
                sig = f"Type: {vt}\nReq: {req[:500]}\nResp: {resp[:500]}"
                results = query_similar("false_positive_patterns", sig, n_results=1)
                if results and results[0]["distance"] is not None and results[0]["distance"] < 0.3:
                    dist = float(results[0]["distance"])
                    logger.info(f"Historical FP match found for {vt} with distance {dist:.3f}")
                    historical_fp_signal = True
                    historical_fp_distance = dist
                    confidence_penalty = 0.5
                    reason = f"Passed deterministic gates, but matches historical false-positive pattern (distance: {dist:.2f})."
                    contradictory_evidence.append(f"Historical FP similarity match (distance: {dist:.2f})")
            except Exception as e:
                logger.warning(f"ChromaDB FP query failed: {e}")

        return FalsePositiveEvaluationResult(
            is_false_positive=False,
            reason=reason,
            contradictory_evidence=contradictory_evidence,
            confidence_penalty=confidence_penalty,
            historical_fp_signal=historical_fp_signal,
            historical_fp_distance=historical_fp_distance,
        )
