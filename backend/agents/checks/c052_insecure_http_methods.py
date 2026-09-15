"""C052 — Insecure HTTP Methods Enabled Check for AihaX."""

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


class C052InsecureHTTPMethods(BaseCheck):
    contract = CheckContract(
        id="C052_Insecure_HTTP_Methods",
        name="Insecure HTTP Methods Enabled",
        category=CheckCategory.MISCONFIG,
        description="Detects dangerous or debugging HTTP methods enabled on web endpoints, such as TRACE / TRACK (enabling Cross-Site Tracing / XST) or unauthenticated PUT / DELETE.",
        severity=Severity.LOW,
        vulnerability_type="Security Misconfiguration",
        cwe="CWE-749",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="Web servers must disable TRACE, TRACK, and unauthenticated arbitrary HTTP verbs",
        remediation_guidance="Disable TRACE and TRACK methods in the web server configuration (e.g. TraceEnable Off in Apache).",
        references=[
            "https://cwe.mitre.org/data/definitions/749.html",
            "https://owasp.org/www-community/attacks/Cross_Site_Tracing",
        ],
        verification_strategy="http_response_property",
        required_evidence=["affected_url", "proof_response", "enabled_methods"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        # Test TRACE method
        trace_spec = RequestSpec(
            url=target_url,
            method="TRACE",
            headers={"X-Aihax-Trace-Probe": "canary_probe_123"},
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        trace_resp = await request_engine.execute(trace_spec)
        if trace_resp.success and trace_resp.response_status == 200:
            body = trace_resp.response_body or ""
            if "X-Aihax-Trace-Probe: canary_probe_123" in body or "TRACE" in body:
                return CheckResult(
                    check_id=self.contract.id,
                    title=f"{self.contract.name} (TRACE Enabled)",
                    target=target_url,
                    affected_url=target_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.LOW,
                    candidate_reason="HTTP TRACE method is enabled and actively echoing request headers back to the client.",
                    request_ids=[trace_resp.request_id],
                    evidence_ids=[trace_resp.evidence_id],
                    observed_data={"method": "TRACE", "status": trace_resp.response_status},
                    payload="TRACE / HTTP/1.1",
                    proof_response=f"HTTP TRACE Echo Response: {body[:150]}",
                    confidence=95,
                    verification_status="CANDIDATE",
                )

        # Test OPTIONS method for Allow header
        options_spec = RequestSpec(
            url=target_url,
            method="OPTIONS",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        options_resp = await request_engine.execute(options_spec)
        if options_resp.success:
            allow_hdr = options_resp.response_headers.get("allow", "").upper()
            if "TRACE" in allow_hdr or "TRACK" in allow_hdr:
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=target_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.LOW,
                    candidate_reason=f"Server advertises dangerous methods in Allow header: '{allow_hdr}'.",
                    request_ids=[options_resp.request_id],
                    evidence_ids=[options_resp.evidence_id],
                    observed_data={"allow_header": allow_hdr},
                    payload="OPTIONS / HTTP/1.1",
                    proof_response=f"Allow Header: {allow_hdr}",
                    confidence=90,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C052InsecureHTTPMethods)
