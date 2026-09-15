"""C050 — MIME Sniffing Vulnerability Check for AihaX."""

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


class C050MIMESniffing(BaseCheck):
    contract = CheckContract(
        id="C050_MIME_Sniffing",
        name="MIME Sniffing Vulnerability",
        category=CheckCategory.MISCONFIG,
        description="Detects missing 'X-Content-Type-Options: nosniff' header, allowing browsers to perform MIME-type sniffing and execute non-executable file types as HTML or JavaScript.",
        severity=Severity.LOW,
        vulnerability_type="Security Misconfiguration",
        cwe="CWE-706",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="All HTTP responses must declare 'X-Content-Type-Options: nosniff' to disable MIME sniffing",
        remediation_guidance="Add the 'X-Content-Type-Options: nosniff' header to all server responses.",
        references=[
            "https://cwe.mitre.org/data/definitions/116.html",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
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

        headers_lower = {k.lower(): v for k, v in resp.response_headers.items()}
        x_content_type_options = headers_lower.get("x-content-type-options", "").lower()

        if "nosniff" not in x_content_type_options:
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=Severity.LOW,
                candidate_reason="Response lacks 'X-Content-Type-Options: nosniff' header.",
                request_ids=[resp.request_id],
                evidence_ids=[resp.evidence_id],
                observed_data={"x_content_type_options": x_content_type_options},
                payload=None,
                proof_response="Missing X-Content-Type-Options: nosniff",
                confidence=95,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C050MIMESniffing)
