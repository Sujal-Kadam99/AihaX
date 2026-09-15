"""C041 — Attribute Context Injection Check for AihaX."""

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


class C041AttributeContextInjection(BaseCheck):
    contract = CheckContract(
        id="C041_Attribute_Context_Injection",
        name="Attribute Context Injection",
        category=CheckCategory.XSS,
        description="Detects attribute breakout vulnerabilities where unescaped double or single quotes reflected inside HTML attribute values (value=\"...\", placeholder=\"...\") permit injecting arbitrary HTML attributes.",
        severity=Severity.HIGH,
        vulnerability_type="Cross-Site Scripting",
        cwe="CWE-79",
        owasp_category="A03:2021-Injection",
        security_property="User parameters placed within HTML attribute values must encode quotation marks (&quot; &#x27;)",
        remediation_guidance="Attribute-encode all user input placed inside tag attributes (converting quotes to &quot; / &#39;).",
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#rule-2-attribute-encode-before-inserting-untrusted-data-into-html-common-attributes",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "injected_attribute"],
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
            params = {"val": ["default"]}

        canary_attr = 'test" aihax-attr="injected_proof_123'
        for param_name in list(params.keys()):
            test_params = dict(params)
            test_params[param_name] = [canary_attr]
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
            # If the quote breakout is reflected verbatim with unencoded quotes
            if 'aihax-attr="injected_proof_123"' in body or 'aihax-attr="injected_proof_123' in body:
                if "&quot;" not in body:
                    return CheckResult(
                        check_id=self.contract.id,
                        title=self.contract.name,
                        target=target_url,
                        affected_url=test_url,
                        affected_param=param_name,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.HIGH,
                        candidate_reason=f"Attribute injection breakout successful: Injected custom attribute '{canary_attr}' via parameter '{param_name}'.",
                        request_ids=[resp.request_id],
                        evidence_ids=[resp.evidence_id],
                        observed_data={"param": param_name, "injected_attr": canary_attr},
                        payload=canary_attr,
                        proof_response=f"Attribute Breakout Reflected: {canary_attr}",
                        confidence=95,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C041AttributeContextInjection)
