"""C030 — CRLF Injection / Response Splitting Check for AihaX."""

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


class C030CRLFInjection(BaseCheck):
    contract = CheckContract(
        id="C030_CRLF_Injection",
        name="CRLF Injection / HTTP Response Splitting",
        category=CheckCategory.INJECTION,
        description="Detects Carriage Return Line Feed (CRLF) Injection allowing attackers to inject arbitrary headers (such as Set-Cookie) or split HTTP response bodies.",
        severity=Severity.HIGH,
        vulnerability_type="CRLF Injection",
        cwe="CWE-113",
        owasp_category="A03:2021-Injection",
        security_property="HTTP response headers must reject carriage return and newline characters to prevent response splitting",
        remediation_guidance="Disallow or percent-encode CR (\\r) and LF (\\n) characters in all parameter values before incorporating them into redirects or response headers.",
        references=[
            "https://cwe.mitre.org/data/definitions/113.html",
            "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
        ],
        verification_strategy="http_response_property",
        required_evidence=["affected_url", "proof_response", "injected_cookie"],
        destructive=False,
    )

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

        crlf_cookie = "aihax_crlf_test=injected_123"
        payload = f"test%0d%0aSet-Cookie:+{crlf_cookie}"

        for param_name in list(params.keys()):
            test_params = dict(params)
            test_params[param_name] = [payload]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            spec = RequestSpec(
                url=test_url,
                method="GET",
                follow_redirects=False,
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            resp = await request_engine.execute(spec)
            if not resp.success:
                continue

            set_cookies = [v for k, v in resp.response_headers.items() if k.lower() == "set-cookie"]
            if any("aihax_crlf_test" in c for c in set_cookies):
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=test_url,
                    affected_param=param_name,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.HIGH,
                    candidate_reason=f"CRLF injection successfully injected a 'Set-Cookie: {crlf_cookie}' header via parameter '{param_name}'.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"param": param_name, "injected_cookie": crlf_cookie},
                    payload=payload,
                    proof_response=f"Injected Set-Cookie Header: {crlf_cookie}",
                    confidence=95,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C030CRLFInjection)
