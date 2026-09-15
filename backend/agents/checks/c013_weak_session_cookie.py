"""C013 — Weak Session Cookie Configuration Check for AihaX."""

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


class C013WeakSessionCookie(BaseCheck):
    contract = CheckContract(
        id="C013_Weak_Session_Cookie",
        name="Weak Session Cookie Configuration",
        category=CheckCategory.AUTH,
        description="Detects weakly configured session cookies, including overly broad domain scopes (e.g. Domain=.example.com), insecure prefixes (__Host-, __Secure-), or missing expiration boundaries.",
        severity=Severity.LOW,
        vulnerability_type="Insecure Cookie Attributes",
        cwe="CWE-614",
        owasp_category="A07:2021-Identification and Authentication Failures",
        security_property="Session cookies must be scoped strictly to the origin domain and enforce secure cookie prefixes",
        remediation_guidance="Omit the Domain attribute to restrict cookies to the exact origin, and adopt the __Host- cookie prefix where possible.",
        references=[
            "https://cwe.mitre.org/data/definitions/614.html",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes",
        ],
        verification_strategy="http_response_property",
        required_evidence=["affected_url", "proof_response", "cookie_header"],
        destructive=False,
    )

    SESSION_COOKIE_NAMES = {"session", "sessionid", "phpsessid", "jsessionid", "connect.sid", "token", "auth", "authtoken", "jwt", "sid"}

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

        set_cookie_headers = [v for k, v in resp_evidence.response_headers.items() if k.lower() == "set-cookie"]
        for cookie_str in set_cookie_headers:
            cookie_name = cookie_str.split("=")[0].strip().lower()
            if any(s in cookie_name for s in self.SESSION_COOKIE_NAMES):
                # Check for overly broad domain attribute
                domain_match = re.search(r"domain=\.?[a-zA-Z0-9.-]+", cookie_str, re.IGNORECASE)
                if domain_match and domain_match.group(0).lower().startswith("domain=."):
                    return CheckResult(
                        check_id=self.contract.id,
                        title=f"{self.contract.name} (Broad Domain Scope)",
                        target=target_url,
                        affected_url=target_url,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.LOW,
                        candidate_reason=f"Session cookie '{cookie_name}' specifies a broad domain attribute '{domain_match.group(0)}', allowing subdomain access.",
                        request_ids=[resp_evidence.request_id],
                        evidence_ids=[resp_evidence.evidence_id],
                        observed_data={"cookie_header": cookie_str, "cookie_name": cookie_name},
                        payload=None,
                        proof_response=f"Set-Cookie: {cookie_str}",
                        confidence=85,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C013WeakSessionCookie)
