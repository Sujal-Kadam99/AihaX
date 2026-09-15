"""C043 — URL Context Injection Check for AihaX."""

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


class C043URLContextInjection(BaseCheck):
    contract = CheckContract(
        id="C043_URL_Context_Injection",
        name="URL Context Injection",
        category=CheckCategory.XSS,
        description="Detects URI scheme injection vulnerabilities where input placed into hyperlink or resource attributes (href, src, action) accepts pseudo-protocols like 'javascript:' or 'data:'.",
        severity=Severity.HIGH,
        vulnerability_type="Cross-Site Scripting",
        cwe="CWE-79",
        owasp_category="A03:2021-Injection",
        security_property="URL attributes must validate destination schemes and reject javascript:, data:, and vbscript: URIs",
        remediation_guidance="Validate and enforce an explicit allowlist of URL protocols (http, https) before rendering user URLs into href or src attributes.",
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#rule-4-css-encode-and-strictly-validate-before-inserting-untrusted-data-into-html-style-property-values",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "injected_scheme"],
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
            params = {"next": ["/home"]}

        js_scheme_payload = "javascript:void(aihax_url_proof)"
        for param_name in list(params.keys()):
            test_params = dict(params)
            test_params[param_name] = [js_scheme_payload]
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
            # If javascript: scheme is reflected inside href/src attributes
            if 'href="javascript:void(aihax_url_proof)"' in body or "href='javascript:void(aihax_url_proof)'" in body:
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=test_url,
                    affected_param=param_name,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.HIGH,
                    candidate_reason=f"Dangerous 'javascript:' URI scheme was accepted and reflected inside an HTML href attribute via parameter '{param_name}'.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"param": param_name, "injected_scheme": js_scheme_payload},
                    payload=js_scheme_payload,
                    proof_response=f"Injected Scheme in Anchor: href=\"{js_scheme_payload}\"",
                    confidence=95,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C043URLContextInjection)
