"""C044 — Mutation-Based XSS (mXSS) Indicators Check for AihaX."""

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


class C044MutationXSS(BaseCheck):
    contract = CheckContract(
        id="C044_Mutation_XSS",
        name="Mutation-Based XSS Indicators",
        category=CheckCategory.XSS,
        description="Detects mutation-based Cross-Site Scripting (mXSS) indicators where parser namespace transitions (e.g. <math>, <svg>, foreignObject) alter the DOM structure during innerHTML serialization.",
        severity=Severity.HIGH,
        vulnerability_type="Cross-Site Scripting",
        cwe="CWE-79",
        owasp_category="A03:2021-Injection",
        security_property="HTML sanitization libraries must guard against namespace confusion mutations in MathML and SVG contexts",
        remediation_guidance="Use up-to-date DOMPurify sanitization with strict MathML/SVG namespace enforcement.",
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-bypass/",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "mxss_payload"],
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
            params = {"content": ["test"]}

        mxss_probe = "<math><mtext><table><mglyph>aihax_mxss_canary"
        for param_name in list(params.keys()):
            test_params = dict(params)
            test_params[param_name] = [mxss_probe]
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
            if "<math><mtext><table>" in body or "<mglyph>aihax_mxss_canary" in body:
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=test_url,
                    affected_param=param_name,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.HIGH,
                    candidate_reason=f"Mutation XSS MathML namespace payload was reflected unescaped via parameter '{param_name}'.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"param": param_name, "mxss_probe": mxss_probe},
                    payload=mxss_probe,
                    proof_response=f"Unescaped MathML Namespace Tag Reflected: {mxss_probe}",
                    confidence=90,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C044MutationXSS)
