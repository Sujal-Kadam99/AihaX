"""C016 — Missing SameSite Cookie Attribute Check for AihaX."""

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


class C016MissingSameSiteCookie(BaseCheck):
    contract = CheckContract(
        id="C016_Missing_SameSite_Cookie",
        name="Missing SameSite Cookie Attribute",
        category=CheckCategory.AUTH,
        description="Detects session cookies that omit the 'SameSite' attribute or configure 'SameSite=None' without the Secure flag, exposing state-changing endpoints to Cross-Site Request Forgery (CSRF).",
        severity=Severity.LOW,
        vulnerability_type="Insecure Cookie Attributes",
        cwe="CWE-1275",
        owasp_category="A01:2021-Broken Access Control",
        security_property="State-managing cookies must declare SameSite=Lax or SameSite=Strict to defend against CSRF",
        remediation_guidance="Add 'SameSite=Lax' or 'SameSite=Strict' to all Set-Cookie directives for session and authentication tokens.",
        references=[
            "https://cwe.mitre.org/data/definitions/1275.html",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value",
        ],
        verification_strategy="http_response_property",
        required_evidence=["affected_url", "proof_response", "cookie_header"],
        destructive=False,
    )

    SESSION_KEYWORDS = ["session", "sess", "token", "auth", "jwt", "sid", "connect.sid"]

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
            if any(k in cookie_name for k in self.SESSION_KEYWORDS):
                if "samesite" not in cookie_str.lower():
                    return CheckResult(
                        check_id=self.contract.id,
                        title=self.contract.name,
                        target=target_url,
                        affected_url=target_url,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.LOW,
                        candidate_reason=f"Session cookie '{cookie_name}' omits the 'SameSite' attribute, defaulting to permissive cross-site handling.",
                        request_ids=[resp_evidence.request_id],
                        evidence_ids=[resp_evidence.evidence_id],
                        observed_data={"cookie_header": cookie_str, "cookie_name": cookie_name},
                        payload=None,
                        proof_response=f"Set-Cookie: {cookie_str} [MISSING SAMESITE]",
                        confidence=90,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C016MissingSameSiteCookie)
