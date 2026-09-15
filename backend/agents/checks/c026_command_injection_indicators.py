"""C026 — Command Injection Indicators Check for AihaX."""

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


class C026CommandInjectionIndicators(BaseCheck):
    contract = CheckContract(
        id="C026_Command_Injection_Indicators",
        name="Command Injection Indicators",
        category=CheckCategory.INJECTION,
        description="Detects OS command injection indicators and shell syntax error disclosures triggered by command chaining metacharacters (; & | ` $).",
        severity=Severity.CRITICAL,
        vulnerability_type="Command Injection",
        cwe="CWE-78",
        owasp_category="A03:2021-Injection",
        security_property="System shell execution functions must never evaluate unsanitized user inputs or shell delimiters",
        remediation_guidance="Avoid executing operating system commands through shell wrappers (e.g. exec/system); use parameterized process APIs without shell invocation.",
        references=[
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "command_error_signature"],
        destructive=False,
    )

    SHELL_ERRORS = [
        re.compile(r"sh:\s*1:\s*.*:\s*not found", re.I),
        re.compile(r"/bin/sh:\s*.*:\s*command not found", re.I),
        re.compile(r"/bin/bash:\s*.*:\s*command not found", re.I),
        re.compile(r"is not recognized as an internal or external command", re.I),
        re.compile(r"the system cannot find the path specified", re.I),
        re.compile(r"syntax error near unexpected token", re.I),
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
            params = {"cmd": ["test"]}

        for param_name in list(params.keys()):
            for payload in ["; aihax_nonexistent_cmd_xyz", "| aihax_nonexistent_cmd_xyz", "`aihax_nonexistent_cmd_xyz`"]:
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
                for err_pat in self.SHELL_ERRORS:
                    match = err_pat.search(body)
                    if match:
                        snippet = body[max(0, match.start() - 20) : min(len(body), match.end() + 50)].replace("\n", " ")
                        return CheckResult(
                            check_id=self.contract.id,
                            title=self.contract.name,
                            target=target_url,
                            affected_url=test_url,
                            affected_param=param_name,
                            vulnerability_type=self.contract.vulnerability_type,
                            severity=Severity.CRITICAL,
                            candidate_reason=f"Target disclosed shell execution error when injected with delimiter payload '{payload}' on parameter '{param_name}'.",
                            request_ids=[resp.request_id],
                            evidence_ids=[resp.evidence_id],
                            observed_data={"param": param_name, "error_snippet": snippet},
                            payload=payload,
                            proof_response=f"Shell Error Disclosed: {snippet}",
                            confidence=90,
                            verification_status="CANDIDATE",
                        )

        return None


# Register check
registry.register(C026CommandInjectionIndicators)
