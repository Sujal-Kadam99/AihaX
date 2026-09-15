"""C015 — Missing HttpOnly Cookie Attribute Check for AihaX."""

from __future__ import annotations

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


class C015MissingHttpOnlyCookie(BaseCheck):
    contract = CheckContract(
        id="C015_Missing_HttpOnly_Cookie",
        name="Missing HttpOnly Cookie Attribute",
        category=CheckCategory.AUTH,
        description="Detects session and authentication cookies issued without the 'HttpOnly' attribute, allowing client-side scripts to access session tokens in the event of XSS.",
        severity=Severity.MEDIUM,
        vulnerability_type="Insecure Cookie Attributes",
        cwe="CWE-1004",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="Authentication and session tokens must include the HttpOnly flag to prevent script access",
        remediation_guidance="Set the 'HttpOnly' flag on all sensitive cookies in Set-Cookie response headers.",
        references=[
            "https://cwe.mitre.org/data/definitions/1004.html",
            "https://owasp.org/www-community/HttpOnly",
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
                if "httponly" not in cookie_str.lower():
                    return CheckResult(
                        check_id=self.contract.id,
                        title=self.contract.name,
                        target=target_url,
                        affected_url=target_url,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.MEDIUM,
                        candidate_reason=f"Authentication cookie '{cookie_name}' lacks the 'HttpOnly' attribute.",
                        request_ids=[resp_evidence.request_id],
                        evidence_ids=[resp_evidence.evidence_id],
                        observed_data={"cookie_header": cookie_str, "cookie_name": cookie_name},
                        payload=None,
                        proof_response=f"Set-Cookie: {cookie_str} [MISSING HTTPONLY]",
                        confidence=95,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C015MissingHttpOnlyCookie)
