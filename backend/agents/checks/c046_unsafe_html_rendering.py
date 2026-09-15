"""C046 — Unsafe HTML Rendering Check for AihaX."""

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


class C046UnsafeHTMLRendering(BaseCheck):
    contract = CheckContract(
        id="C046_Unsafe_HTML_Rendering",
        name="Unsafe HTML Rendering",
        category=CheckCategory.XSS,
        description="Detects rich-text and Markdown renderers that permit raw HTML tags and unsafe iframe/object embeddings without sanitizing the rendered HTML output.",
        severity=Severity.HIGH,
        vulnerability_type="Cross-Site Scripting",
        cwe="CWE-79",
        owasp_category="A03:2021-Injection",
        security_property="Markdown and rich-text renderers must escape or sanitize embedded raw HTML tags",
        remediation_guidance="Configure Markdown renderers to escape HTML or post-process rendered HTML with DOMPurify.",
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "rendered_html_tag"],
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
            params = {"md": ["# Heading"]}

        markdown_probe = "# Test\n<iframe src=\"about:blank\" aihax-render-canary=1></iframe>"
        for param_name in list(params.keys()):
            test_params = dict(params)
            test_params[param_name] = [markdown_probe]
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
            # If the raw iframe tag was rendered into the HTML DOM without sanitization
            if '<iframe src="about:blank" aihax-render-canary=1></iframe>' in body or "aihax-render-canary=1" in body:
                if "&lt;iframe" not in body:
                    return CheckResult(
                        check_id=self.contract.id,
                        title=self.contract.name,
                        target=target_url,
                        affected_url=test_url,
                        affected_param=param_name,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.HIGH,
                        candidate_reason=f"Markdown/rich-text renderer rendered raw unsafe HTML tag '<iframe ...>' unescaped via parameter '{param_name}'.",
                        request_ids=[resp.request_id],
                        evidence_ids=[resp.evidence_id],
                        observed_data={"param": param_name, "rendered_tag": "<iframe src=\"about:blank\" aihax-render-canary=1></iframe>"},
                        payload=markdown_probe,
                        proof_response="Raw HTML Tag Rendered in Output: <iframe ... aihax-render-canary=1></iframe>",
                        confidence=90,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C046UnsafeHTMLRendering)
