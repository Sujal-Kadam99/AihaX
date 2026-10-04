"""C085 — Missing OAuth state Parameter (CSRF on OAuth flow) Check for AihaX."""

from __future__ import annotations

from typing import Any, Dict, Optional
import urllib.parse

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C085MissingOAuthStateParameter(BaseCheck):
    contract = CheckContract(
        id="C085_Missing_OAuth_State_Parameter",
        name="Missing OAuth state Parameter (CSRF on OAuth flow)",
        category=CheckCategory.AUTH,
        description="Detects OAuth 2.0 authorization requests initiated without an unpredictable state parameter, exposing users to OAuth login CSRF.",
        severity=Severity.MEDIUM,
        vulnerability_type="OAuth CSRF Flaw",
        cwe="CWE-352",
        owasp_category="A01:2021-Broken Access Control",
        security_property="OAuth authorization requests must include an unguessable state parameter bound to the user's browser session.",
        remediation_guidance="Generate and validate a cryptographically secure, session-bound state parameter in all OAuth authorization requests.",
        references=["https://portswigger.net/web-security/oauth"],
        verification_strategy="oauth_state_parameter",
        required_evidence=["affected_url", "proof_request"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        
        # If this is an OAuth auth request and state is absent
        is_oauth = "client_id" in params or "redirect_uri" in params or "oauth" in parsed.path.lower()
        if is_oauth and "state" not in params:
            spec = RequestSpec(
                url=target_url,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )

            resp_evidence = await request_engine.execute(spec)
            if not resp_evidence.success:
                return None

            status = resp_evidence.response_status
            if status in (200, 302):
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=target_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=self.contract.severity,
                    candidate_reason="OAuth authorization flow initiated without requiring or validating an anti-CSRF state parameter.",
                    request_ids=[resp_evidence.request_id],
                    evidence_ids=[resp_evidence.evidence_id],
                    observed_data={"missing_parameter": "state", "status": status},
                    payload="state omitted",
                    proof_request=f"GET {target_url} HTTP/1.1",
                    proof_response=f"HTTP/1.1 {status}\r\nLocation: {resp_evidence.response_headers.get('location', '')}",
                    confidence=70,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C085MissingOAuthStateParameter)
