"""C014 — Missing Secure Cookie Attribute Check for AihaX."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C014MissingSecureCookie(BaseCheck):
    contract = CheckContract(
        id="C014_Missing_Secure_Cookie",
        name="Missing Secure Cookie Attribute",
        category=CheckCategory.AUTH,
        description="Detects session and authentication cookies transmitted without the 'Secure' attribute, exposing credentials to cleartext interception over insecure HTTP channels.",
        severity=Severity.MEDIUM,
        vulnerability_type="Insecure Cookie Attributes",
        cwe="CWE-614",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="Sensitive session and authentication cookies must always include the Secure flag",
        remediation_guidance="Add the 'Secure' attribute to all Set-Cookie headers for sensitive authentication tokens.",
        references=[
            "https://cwe.mitre.org/data/definitions/614.html",
            "https://owasp.org/www-community/controls/SecureCookieAttribute",
        ],
        verification_strategy="http_response_property",
        required_evidence=["affected_url", "proof_response", "cookie_header"],
        destructive=False,
    )

    SESSION_KEYWORDS = ["session", "sess", "token", "auth", "jwt", "sid", "user", "id"]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        spec = RequestSpec(
            url=target_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp_evidence = await request_engine.execute(spec)
        if not resp_evidence.success:
            return None

        set_cookies = [v for k, v in resp_evidence.response_headers.items() if k.lower() == "set-cookie"]
        for cookie_str in set_cookies:
            cookie_name = cookie_str.split("=")[0].strip().lower()
            # If cookie appears to be authentication or session related
            if any(k in cookie_name for k in self.SESSION_KEYWORDS):
                if "secure" not in cookie_str.lower():
                    return CheckResult(
                        check_id=self.contract.id,
                        title=self.contract.name,
                        target=target_url,
                        affected_url=target_url,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.MEDIUM,
                        candidate_reason=f"Session cookie '{cookie_name}' was issued without the mandatory 'Secure' attribute.",
                        request_ids=[resp_evidence.request_id],
                        evidence_ids=[resp_evidence.evidence_id],
                        observed_data={"cookie_header": cookie_str, "cookie_name": cookie_name},
                        payload=None,
                        proof_response=f"Set-Cookie: {cookie_str} [MISSING SECURE]",
                        confidence=95,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C014MissingSecureCookie)
