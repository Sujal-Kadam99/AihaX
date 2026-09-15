"""C059 — PII / Sensitive Data in URL Query Parameters Check for AihaX."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C059PIIURLExposure(BaseCheck):
    contract = CheckContract(
        id="C059_PII_URL_Exposure",
        name="PII / Sensitive Data in URL Query Parameters",
        category=CheckCategory.SENSITIVE_DATA,
        description="Detects sensitive credentials, passwords, authentication tokens, API keys, or personally identifiable information (PII) transmitted via URL query parameters, leaking into server access logs, browser history, and Referer headers.",
        severity=Severity.MEDIUM,
        vulnerability_type="Information Disclosure",
        cwe="CWE-598",
        owasp_category="A04:2021-Insecure Design",
        security_property="Sensitive parameters and authentication credentials must never be passed in GET request URLs",
        remediation_guidance="Transmit authentication tokens and sensitive parameters in HTTP request headers (Authorization) or POST request bodies rather than URL query strings.",
        references=[
            "https://cwe.mitre.org/data/definitions/598.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
        ],
        verification_strategy="http_response_property",
        required_evidence=["affected_url", "proof_response", "sensitive_parameter"],
        destructive=False,
    )

    SENSITIVE_PARAMS = {"password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "access_token", "ssn", "creditcard", "card_number"}

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in list(params.keys()):
            if param_name.lower() in self.SENSITIVE_PARAMS:
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=target_url,
                    affected_param=param_name,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.MEDIUM,
                    candidate_reason=f"Sensitive parameter '{param_name}' transmitted in URL query string, exposing values to browser histories, proxies, and Referer headers.",
                    request_ids=[],
                    evidence_ids=[],
                    observed_data={"parameter": param_name, "query_string": parsed.query},
                    payload=None,
                    proof_response=f"Sensitive query param in URL: '{param_name}'",
                    confidence=95,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C059PIIURLExposure)
