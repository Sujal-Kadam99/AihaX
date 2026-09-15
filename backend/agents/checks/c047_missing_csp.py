"""C047 — Missing Content Security Policy (CSP) Check for AihaX."""

from __future__ import annotations

from typing import Any, Dict, Optional

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C047MissingCSP(BaseCheck):
    contract = CheckContract(
        id="C047_Missing_CSP",
        name="Missing Content Security Policy (CSP)",
        category=CheckCategory.MISCONFIG,
        description="Detects missing Content-Security-Policy HTTP response headers on HTML endpoints, depriving browsers of defense-in-depth mitigation against Cross-Site Scripting (XSS) and data injection.",
        severity=Severity.MEDIUM,
        vulnerability_type="Security Misconfiguration",
        cwe="CWE-693",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="HTML endpoints must supply a Content-Security-Policy header restricting script and object sources",
        remediation_guidance="Implement a Content-Security-Policy (CSP) header specifying trusted sources for scripts, styles, objects, and framing.",
        references=[
            "https://cwe.mitre.org/data/definitions/1021.html",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        ],
        verification_strategy="http_response_property",
        required_evidence=["affected_url", "proof_response", "headers_analyzed"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        spec = RequestSpec(
            url=target_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp = await request_engine.execute(spec)
        if not resp.success:
            return None

        content_type = resp.response_headers.get("content-type", "").lower()
        if "html" not in content_type and content_type:
            return None

        headers_lower = {k.lower(): v for k, v in resp.response_headers.items()}
        if "content-security-policy" not in headers_lower and "content-security-policy-report-only" not in headers_lower:
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=Severity.MEDIUM,
                candidate_reason="HTML response lacks both 'Content-Security-Policy' and 'Content-Security-Policy-Report-Only' headers.",
                request_ids=[resp.request_id],
                evidence_ids=[resp.evidence_id],
                observed_data={"content_type": content_type, "status": resp.response_status},
                payload=None,
                proof_response="Missing Content-Security-Policy in response headers",
                confidence=95,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C047MissingCSP)
