"""C045 — XSS Filter / Sanitization Bypass Indicators Check for AihaX."""

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


class C045XSSFilterBypass(BaseCheck):
    contract = CheckContract(
        id="C045_XSS_Filter_Bypass",
        name="XSS Filter / Sanitization Bypass Indicators",
        category=CheckCategory.XSS,
        description="Detects naive blacklist-based XSS filtering weaknesses bypassed via mixed casing (<sCrIpt>), nested tags (<scr<script>ipt>), or event handlers (<img src=x onerror=canary>).",
        severity=Severity.HIGH,
        vulnerability_type="Cross-Site Scripting",
        cwe="CWE-79",
        owasp_category="A03:2021-Injection",
        security_property="HTML input filters must not rely on case-sensitive string matching or single-pass regex replacement",
        remediation_guidance="Replace custom regex/blacklist filtering with established context-aware HTML entity encoders or robust HTML parsers like DOMPurify.",
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://owasp.org/www-community/xss-filter-evasion-cheatsheet",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "bypassed_payload"],
        destructive=False,
    )

    BYPASS_PROBES = [
        ("<sCrIpt>aihax_bypass_canary=1</sCrIpt>", "Mixed Case Tag (<sCrIpt>)"),
        ("<img src=x onerror=aihax_bypass_canary=1>", "Event Handler (<img src=x onerror=...>)"),
        ("<svg/onload=aihax_bypass_canary=1>", "SVG Event Handler (<svg/onload=...>)"),
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            params = {"search": ["test"]}

        for param_name in list(params.keys()):
            for probe, technique in self.BYPASS_PROBES:
                test_params = dict(params)
                test_params[param_name] = [probe]
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
                # If the filter bypass probe reflected intact without HTML entity encoding
                if probe in body and "&lt;" not in body:
                    return CheckResult(
                        check_id=self.contract.id,
                        title=f"{self.contract.name} ({technique})",
                        target=target_url,
                        affected_url=test_url,
                        affected_param=param_name,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.HIGH,
                        candidate_reason=f"XSS filter bypass successful: {technique} '{probe}' was reflected unencoded via parameter '{param_name}'.",
                        request_ids=[resp.request_id],
                        evidence_ids=[resp.evidence_id],
                        observed_data={"param": param_name, "technique": technique, "probe": probe},
                        payload=probe,
                        proof_response=f"Bypassed Filter Reflection: {probe}",
                        confidence=90,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C045XSSFilterBypass)
