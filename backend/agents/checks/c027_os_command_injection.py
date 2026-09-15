"""C027 — OS Command Injection Check for AihaX."""

from __future__ import annotations

import re
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


class C027OSCommandInjection(BaseCheck):
    contract = CheckContract(
        id="C027_OS_Command_Injection",
        name="OS Command Injection",
        category=CheckCategory.INJECTION,
        description="Detects active operating system command injection vulnerabilities via deterministic arithmetic execution (e.g. expr 31330 + 7 yielding 31337).",
        severity=Severity.CRITICAL,
        vulnerability_type="OS Command Injection",
        cwe="CWE-78",
        owasp_category="A03:2021-Injection",
        security_property="Parameters must not be executed or evaluated in an operating system subshell",
        remediation_guidance="Disallow execution of operating system commands from web input and use native language APIs instead of subshell invocations.",
        references=[
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://portswigger.net/web-security/os-command-injection",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "evaluated_canary"],
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
            params = {"ip": ["127.0.0.1"]}

        # Step 1: Baseline request to prevent false positives on static body content
        base_spec = RequestSpec(
            url=target_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        base_resp = await request_engine.execute(base_spec)
        base_body = base_resp.response_body if base_resp.success else ""

        canary_expected = "31337"
        payloads = [
            f"; expr 31330 + 7 ;",
            f"| expr 31330 + 7",
            f"$(expr 31330 + 7)",
            f"`expr 31330 + 7`",
        ]
        if canary_expected in base_body:
            canary_expected = "54321"
            payloads = [
                "; expr 54310 + 11 ;",
                "| expr 54310 + 11",
                "$(expr 54310 + 11)",
                "`expr 54310 + 11`",
            ]

        for param_name in list(params.keys()):
            for payload in payloads:
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

                body = resp.response_body or ""
                # If arithmetic result 31337 is rendered in body and not part of the raw payload string
                if canary_expected in body and "31330 + 7" not in body:
                    return CheckResult(
                        check_id=self.contract.id,
                        title=self.contract.name,
                        target=target_url,
                        affected_url=test_url,
                        affected_param=param_name,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.CRITICAL,
                        candidate_reason=f"Target evaluated shell arithmetic command '{payload}' yielding calculated output '{canary_expected}' on parameter '{param_name}'.",
                        request_ids=[resp.request_id],
                        evidence_ids=[resp.evidence_id],
                        observed_data={"param": param_name, "canary_evaluated": canary_expected},
                        payload=payload,
                        proof_response=f"Command Output Evaluated: '{canary_expected}' in response body",
                        confidence=95,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C027OSCommandInjection)
