"""C042 — JavaScript Context Injection Check for AihaX."""

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


class C042JavaScriptContextInjection(BaseCheck):
    contract = CheckContract(
        id="C042_JavaScript_Context_Injection",
        name="JavaScript Context Injection",
        category=CheckCategory.XSS,
        description="Detects script context breakout vulnerabilities where user parameters placed inside inline <script> variables (var data = 'USER_INPUT') are unescaped and allow script execution.",
        severity=Severity.HIGH,
        vulnerability_type="Cross-Site Scripting",
        cwe="CWE-79",
        owasp_category="A03:2021-Injection",
        security_property="User data embedded in JavaScript blocks must be encoded using JavaScript hexadecimal encoding (\\xHH / \\uHHHH)",
        remediation_guidance="JavaScript-encode all user input placed inside script blocks or serialize data securely using JSON.parse(JSON.stringify()).",
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#rule-3-javascript-encode-before-inserting-untrusted-data-into-javascript-data-values",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "injected_script_breakout"],
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
            params = {"callback": ["fn"]}

        script_payload = "';aihax_js_proof=1;//"
        for param_name in list(params.keys()):
            test_params = dict(params)
            test_params[param_name] = [script_payload]
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
            if "';aihax_js_proof=1;//" in body or "\\';aihax_js_proof=1" not in body and "aihax_js_proof=1" in body:
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=test_url,
                    affected_param=param_name,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.HIGH,
                    candidate_reason=f"JavaScript block breakout successful: Injected script context payload '{script_payload}' via parameter '{param_name}'.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"param": param_name, "injected_payload": script_payload},
                    payload=script_payload,
                    proof_response=f"Script Context Breakout: {script_payload}",
                    confidence=90,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C042JavaScriptContextInjection)
