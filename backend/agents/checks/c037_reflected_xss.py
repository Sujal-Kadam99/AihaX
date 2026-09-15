"""C037 — Reflected XSS Check for AihaX."""

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


class C037ReflectedXSS(BaseCheck):
    contract = CheckContract(
        id="C037_Reflected_XSS",
        name="Reflected XSS",
        category=CheckCategory.XSS,
        description="Detects Reflected Cross-Site Scripting (XSS) where parameters are unencoded and reflected verbatim into HTML response bodies with executable HTML syntax.",
        severity=Severity.HIGH,
        vulnerability_type="Cross-Site Scripting",
        cwe="CWE-79",
        owasp_category="A03:2021-Injection",
        security_property="User parameters reflected in HTTP response bodies must be contextually encoded (HTML entity encoded)",
        remediation_guidance="HTML-encode all user-supplied data before reflecting it in HTML contexts, and adopt a strict Content-Security-Policy (CSP).",
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "reflected_canary"],
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
            params = {"q": ["test"]}

        canary_tag = "<aihax-xss-canary-777>"
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
            # If the raw unescaped tag is reflected verbatim in response
            if canary_tag in body and "&lt;aihax-xss-canary-777&gt;" not in body:
                content_type = resp.response_headers.get("content-type", "").lower()
                # Ensure response is rendered as HTML, not plain JSON or download
                if "html" in content_type or not content_type:
                    return CheckResult(
                        check_id=self.contract.id,
                        title=self.contract.name,
                        target=target_url,
                        affected_url=test_url,
                        affected_param=param_name,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.HIGH,
                        candidate_reason=f"Raw unencoded HTML tag '{canary_tag}' was reflected verbatim in HTML response via parameter '{param_name}'.",
                        request_ids=[resp.request_id],
                        evidence_ids=[resp.evidence_id],
                        observed_data={"param": param_name, "reflected_canary": canary_tag, "content_type": content_type},
                        payload=canary_tag,
                        proof_response=f"Unencoded HTML Reflection: {canary_tag}",
                        confidence=95,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C037ReflectedXSS)
