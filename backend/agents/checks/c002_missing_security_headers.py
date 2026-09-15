"""C002 — Missing Security Headers Check for AihaX."""

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


class C002MissingSecurityHeaders(BaseCheck):
    contract = CheckContract(
        id="C002_Missing_Security_Headers",
        name="Missing Security Headers",
        category=CheckCategory.RECON,
        description="Detects omission of critical HTTP defense-in-depth headers such as Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy.",
        severity=Severity.LOW,
        vulnerability_type="Security Misconfiguration",
        cwe="CWE-16",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="specified HTTP security response headers are present when required",
        remediation_guidance="Configure the web server to emit modern security headers: Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy.",
        references=["https://owasp.org/www-project-secure-headers/"],
        verification_strategy="http_response_property",
        required_evidence=["affected_url", "required_header"],
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

        resp_evidence = await request_engine.execute(spec)
        if not resp_evidence.success:
            return None

        headers_lower = {k.lower(): v for k, v in resp_evidence.response_headers.items()}
        expected_headers = [
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "content-security-policy",
        ]

        missing = [h for h in expected_headers if h not in headers_lower]
        if missing:
            primary_missing = missing[0]
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=self.contract.severity,
                candidate_reason=f"HTTP response is missing essential security headers: {', '.join(missing)}.",
                request_ids=[resp_evidence.request_id],
                evidence_ids=[resp_evidence.evidence_id],
                observed_data={
                    "missing_headers": missing,
                    "present_headers": list(resp_evidence.response_headers.keys()),
                    "primary_missing_header": primary_missing,
                },
                proof_response=f"Missing: {', '.join(missing)}\r\nObserved headers:\r\n"
                + "\r\n".join(f"{k}: {v}" for k, v in resp_evidence.response_headers.items()),
                confidence=70,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C002MissingSecurityHeaders)
