"""C036 — Server-Side Request Forgery (SSRF) Indicators Check for AihaX."""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C036SSRFIndicators(BaseCheck):
    contract = CheckContract(
        id="C036_SSRF_Indicators",
        name="Server-Side Request Forgery Indicators",
        category=CheckCategory.INJECTION,
        description="Detects Server-Side Request Forgery (SSRF) indicators where parameters accept URL inputs and fetch/proxy the target resource (verified using safe in-scope callbacks without probing cloud metadata or private IP subnets).",
        severity=Severity.HIGH,
        vulnerability_type="Server-Side Request Forgery",
        cwe="CWE-918",
        owasp_category="A10:2021-Server-Side Request Forgery",
        security_property="Server-side URL fetching must strictly validate destinations against an allowlist and block private IP ranges",
        remediation_guidance="Enforce an allowlist of permitted destination domains, disable redirects, and block requests resolving to loopback or RFC-1918 private IP addresses.",
        references=[
            "https://cwe.mitre.org/data/definitions/918.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "fetched_resource"],
        destructive=False,
    )

    SSRF_PARAM_NAMES = ["url", "dest", "destination", "redirect", "uri", "fetch", "link", "target", "webhook", "callback", "feed"]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            params = {"url": ["https://example.com"]}

        # Strictly in-scope safe probe: request the target's own in-scope robots.txt or root
        safe_in_scope_probe = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

        for param_name in list(params.keys()):
            if any(p in param_name.lower() for p in self.SSRF_PARAM_NAMES):
                test_params = dict(params)
                test_params[param_name] = [safe_in_scope_probe]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                spec = RequestSpec(
                    url=test_url,
                    method="GET",
                    timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
                )
                resp = await request_engine.execute(spec)
                if not resp.success:
                    continue

                body = resp.response_body or ""
                # If target server fetched and embedded the robots.txt content
                if "User-agent:" in body or "Disallow:" in body:
                    return CheckResult(
                        check_id=self.contract.id,
                        title=self.contract.name,
                        target=target_url,
                        affected_url=test_url,
                        affected_param=param_name,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.HIGH,
                        candidate_reason=f"Server-Side Request Forgery indicator observed: Parameter '{param_name}' fetched and proxied the in-scope resource '{safe_in_scope_probe}'.",
                        request_ids=[resp.request_id],
                        evidence_ids=[resp.evidence_id],
                        observed_data={"param": param_name, "fetched_url": safe_in_scope_probe},
                        payload=safe_in_scope_probe,
                        proof_response=f"Proxied Resource Content in Response: {body[:150]}",
                        confidence=85,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C036SSRFIndicators)
