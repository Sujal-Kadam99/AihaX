"""C081 — Host Header Injection Check for AihaX."""

from __future__ import annotations

from typing import Any, Dict, Optional
import uuid

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C081HostHeaderInjection(BaseCheck):
    contract = CheckContract(
        id="C081_Host_Header_Injection",
        name="Host Header Injection",
        category=CheckCategory.INJECTION,
        description="Detects dynamic generation of sensitive URLs (password reset, links, redirects) based on unvalidated Host or X-Forwarded-Host headers.",
        severity=Severity.MEDIUM,
        vulnerability_type="Host Header Injection",
        cwe="CWE-116",
        owasp_category="A03:2021-Injection",
        security_property="Web applications must use server-configured canonical hostnames when generating absolute links and redirect targets.",
        remediation_guidance="Use a server-side configured base URL or strictly validate the incoming Host header against an allowlist.",
        references=["https://portswigger.net/web-security/host-header-injection"],
        verification_strategy="host_header_injection",
        required_evidence=["affected_url", "proof_request"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        token = uuid.uuid4().hex[:8]
        injected_host = f"aihax-host-{token}.test"
        
        spec = RequestSpec(
            url=target_url,
            method="GET",
            headers={"Host": injected_host, "X-Forwarded-Host": injected_host},
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        resp_evidence = await request_engine.execute(spec)
        if not resp_evidence.success:
            return None

        body = resp_evidence.response_body or ""
        headers_lower = {k.lower(): v for k, v in resp_evidence.response_headers.items()}
        location = headers_lower.get("location", "")

        # Detect reflection in Location redirect or HTML links/reset forms
        if injected_host in location or f"href=\"http://{injected_host}" in body or f"href=\"https://{injected_host}" in body or f"src=\"http://{injected_host}" in body:
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=self.contract.severity,
                candidate_reason=f"Injected host '{injected_host}' was reflected into actionable response URL or Location header.",
                request_ids=[resp_evidence.request_id],
                evidence_ids=[resp_evidence.evidence_id],
                observed_data={
                    "injected_host": injected_host,
                    "location_header": location,
                },
                payload=f"Host: {injected_host}",
                proof_request=f"GET {target_url} HTTP/1.1\r\nHost: {injected_host}",
                proof_response=f"HTTP/1.1 {resp_evidence.response_status}\r\nLocation: {location}",
                confidence=80,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C081HostHeaderInjection)
