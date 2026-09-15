"""C034 — LDAP Injection Indicators Check for AihaX."""

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


class C034LDAPInjection(BaseCheck):
    contract = CheckContract(
        id="C034_LDAP_Injection",
        name="LDAP Injection Indicators",
        category=CheckCategory.INJECTION,
        description="Detects LDAP query syntax errors and filter structure manipulation indicators resulting from unescaped parentheses and LDAP metacharacters (*, (, ), &).",
        severity=Severity.HIGH,
        vulnerability_type="LDAP Injection",
        cwe="CWE-90",
        owasp_category="A03:2021-Injection",
        security_property="User parameters concatenated into LDAP search filters must properly escape LDAP metacharacters",
        remediation_guidance="Use framework-provided LDAP filter encoding functions or parameterized directory search APIs.",
        references=[
            "https://cwe.mitre.org/data/definitions/90.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "ldap_error_snippet"],
        destructive=False,
    )

    LDAP_ERRORS = [
        re.compile(r"javax\.naming\.directory\.InvalidSearchFilterException", re.I),
        re.compile(r"LDAPException", re.I),
        re.compile(r"IPWorksASP\.LDAP", re.I),
        re.compile(r"supplied argument is not a valid ldap", re.I),
        re.compile(r"Invalid DN syntax", re.I),
        re.compile(r"bad search filter", re.I),
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
            params = {"user": ["admin"]}

        for param_name in list(params.keys()):
            for payload in ["*)(uid=*))(|(uid=*", "*)(cn=*", "admin)(|(password=*"]:
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
                for err_pat in self.LDAP_ERRORS:
                    match = err_pat.search(body)
                    if match:
                        snippet = body[max(0, match.start() - 20) : min(len(body), match.end() + 60)].replace("\n", " ")
                        return CheckResult(
                            check_id=self.contract.id,
                            title=self.contract.name,
                            target=target_url,
                            affected_url=test_url,
                            affected_param=param_name,
                            vulnerability_type=self.contract.vulnerability_type,
                            severity=Severity.HIGH,
                            candidate_reason=f"Target disclosed LDAP filter syntax error when injected with payload '{payload}' on parameter '{param_name}'.",
                            request_ids=[resp.request_id],
                            evidence_ids=[resp.evidence_id],
                            observed_data={"param": param_name, "error_snippet": snippet},
                            payload=payload,
                            proof_response=f"LDAP Error Disclosed: {snippet}",
                            confidence=90,
                            verification_status="CANDIDATE",
                        )

        return None


# Register check
registry.register(C034LDAPInjection)
