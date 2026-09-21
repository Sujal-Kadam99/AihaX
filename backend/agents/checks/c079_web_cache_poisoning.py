"""C079 — Web Cache Poisoning / Cache Deception Check for AihaX."""

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


class C079WebCachePoisoning(BaseCheck):
    contract = CheckContract(
        id="C079_Web_Cache_Poisoning",
        name="Web Cache Poisoning / Cache Deception",
        category=CheckCategory.MISCONFIG,
        description="Detects caching proxies that store and serve responses keyed without unkeyed headers like X-Forwarded-Host.",
        severity=Severity.HIGH,
        vulnerability_type="Web Cache Poisoning",
        cwe="CWE-444",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="Web caching layers must exclude unkeyed headers from influencing cached response content.",
        remediation_guidance="Disable unkeyed header transformations, ensure all headers influencing the response are included in the cache key, or set Cache-Control: private/no-store on dynamic responses.",
        references=["https://portswigger.net/web-security/web-cache-poisoning"],
        verification_strategy="web_cache_poisoning",
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
        canary_host = f"aihax-cache-canary-{token}.test"
        
        # Test request with unkeyed header
        spec = RequestSpec(
            url=target_url,
            method="GET",
            headers={"X-Forwarded-Host": canary_host},
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        resp_evidence = await request_engine.execute(spec)
        if not resp_evidence.success:
            return None

        body = resp_evidence.response_body or ""
        headers_lower = {k.lower(): v for k, v in resp_evidence.response_headers.items()}
        cache_control = headers_lower.get("cache-control", "")

        # Check if unkeyed header is reflected in response
        if canary_host in body or canary_host in str(resp_evidence.response_headers):
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=self.contract.severity,
                candidate_reason=f"Unkeyed header 'X-Forwarded-Host: {canary_host}' was reflected in server response.",
                request_ids=[resp_evidence.request_id],
                evidence_ids=[resp_evidence.evidence_id],
                observed_data={
                    "reflected_header": "X-Forwarded-Host",
                    "canary_host": canary_host,
                    "cache_control": cache_control,
                    "x_cache": headers_lower.get("x-cache", ""),
                },
                payload=f"X-Forwarded-Host: {canary_host}",
                proof_request=f"GET {target_url} HTTP/1.1\r\nX-Forwarded-Host: {canary_host}",
                proof_response=f"HTTP/1.1 {resp_evidence.response_status}\r\nCache-Control: {cache_control}\r\n\r\n{body[:300]}",
                confidence=75,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C079WebCachePoisoning)
