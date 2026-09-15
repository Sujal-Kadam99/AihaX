"""C029 — Header Injection Check for AihaX."""

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


class C029HeaderInjection(BaseCheck):
    contract = CheckContract(
        id="C029_Header_Injection",
        name="Header Injection",
        category=CheckCategory.INJECTION,
        description="Detects HTTP Header Injection vulnerabilities where unvalidated user input is reflected into response headers, allowing response manipulation or header override.",
        severity=Severity.HIGH,
        vulnerability_type="HTTP Header Injection",
        cwe="CWE-113",
        owasp_category="A03:2021-Injection",
        security_property="Header values set by the server must strip carriage return and line feed characters and never accept arbitrary header keys from input",
        remediation_guidance="Sanitize and strip CR (\\r) and LF (\\n) control characters from any parameter before setting HTTP response headers.",
        references=[
            "https://cwe.mitre.org/data/definitions/113.html",
            "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
        ],
        verification_strategy="http_response_property",
        required_evidence=["affected_url", "proof_response", "injected_header"],
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
            params = {"lang": ["en"]}

        canary_header = "x-aihax-canary"
        canary_val = "probe123"
        payload = f"test%0d%0a{canary_header}:+{canary_val}"

        for param_name in list(params.keys()):
            test_params = dict(params)
            test_params[param_name] = [payload]
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

            headers_lower = {k.lower(): v for k, v in resp.response_headers.items()}
            if canary_header in headers_lower and canary_val in headers_lower[canary_header]:
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=test_url,
                    affected_param=param_name,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.HIGH,
                    candidate_reason=f"Header injection confirmed: injected header '{canary_header}: {canary_val}' was observed in HTTP response headers.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"param": param_name, "injected_header": f"{canary_header}: {canary_val}"},
                    payload=payload,
                    proof_response=f"Injected Response Header: {canary_header}: {headers_lower[canary_header]}",
                    confidence=95,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C029HeaderInjection)
