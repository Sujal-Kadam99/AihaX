"""C040 — HTML Context Injection Check for AihaX."""

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


class C040HTMLContextInjection(BaseCheck):
    contract = CheckContract(
        id="C040_HTML_Context_Injection",
        name="HTML Context Injection",
        category=CheckCategory.XSS,
        description="Detects HTML injection into document body contexts where angle brackets (< >) are reflected unencoded, permitting arbitrary HTML tag injection and defacement.",
        severity=Severity.MEDIUM,
        vulnerability_type="HTML Injection",
        cwe="CWE-79",
        owasp_category="A03:2021-Injection",
        security_property="User data reflected inside HTML element bodies must be HTML entity encoded (&lt; &gt;)",
        remediation_guidance="Apply context-aware HTML entity encoding to user data placed in HTML body content.",
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://owasp.org/www-community/attacks/xss/#html-context",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "injected_tag"],
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
            params = {"text": ["sample"]}

        canary_tag = "<u>aihax_html_injection_proof</u>"
        for param_name in list(params.keys()):
            test_params = dict(params)
            test_params[param_name] = [canary_tag]
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
            if canary_tag in body and "&lt;u&gt;" not in body:
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=test_url,
                    affected_param=param_name,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.MEDIUM,
                    candidate_reason=f"HTML injection tag '{canary_tag}' was reflected unencoded in body content via parameter '{param_name}'.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"param": param_name, "injected_tag": canary_tag},
                    payload=canary_tag,
                    proof_response=f"Unencoded HTML Tag Reflected: {canary_tag}",
                    confidence=90,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C040HTMLContextInjection)
