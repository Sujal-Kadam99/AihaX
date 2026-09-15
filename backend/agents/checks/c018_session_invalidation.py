"""C018 — Session Invalidation Failure Check for AihaX."""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlparse

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import AuthenticationContext, RequestEngine, RequestSpec, RequestTimeout


class C018SessionInvalidation(BaseCheck):
    contract = CheckContract(
        id="C018_Session_Invalidation",
        name="Session Invalidation Failure",
        category=CheckCategory.AUTH,
        description="Detects whether session tokens remain valid on the server after an explicit logout operation, allowing replay of expired or logged-out sessions.",
        severity=Severity.MEDIUM,
        vulnerability_type="Session Invalidation Flaw",
        cwe="CWE-613",
        owasp_category="A07:2021-Identification and Authentication Failures",
        security_property="Server-side session state must be destroyed and tokens invalidated immediately upon logout",
        remediation_guidance="Invalidate the session on the server-side database or cache upon receiving a logout request, rather than solely relying on client-side cookie deletion.",
        references=[
            "https://cwe.mitre.org/data/definitions/613.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-termination",
        ],
        verification_strategy="authentication_comparison",
        required_evidence=["affected_url", "proof_response", "replayed_token"],
        destructive=False,
    )

    LOGOUT_PATHS = ["/logout", "/api/logout", "/api/auth/logout", "/auth/logout", "/signout"]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        auth_token = config.get("auth_token") or config.get("bearer_token")
        if not auth_token:
            return None  # Requires an authenticated session context

        auth_ctx = AuthenticationContext(
            name="Session-Invalidation-Test",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        parsed = urlparse(target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        base = target_url.rstrip("/")
        candidate_logout_urls = set()
        for path in self.LOGOUT_PATHS:
            candidate_logout_urls.add(urljoin(origin + "/", path.lstrip("/")))
            candidate_logout_urls.add(urljoin(base + "/", path.lstrip("/")))

        for logout_url in sorted(candidate_logout_urls):
            # Step 1: Call logout endpoint with auth
            logout_spec = RequestSpec(
                url=logout_url,
                method="POST",
                auth_context=auth_ctx,
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            logout_resp = await request_engine.execute(logout_spec)
            if not logout_resp.success or logout_resp.response_status not in (200, 204, 302):
                continue

            # Step 2: Test if protected target_url STILL responds 200 with the "logged out" token
            verify_spec = RequestSpec(
                url=target_url,
                method="GET",
                auth_context=auth_ctx,
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            verify_resp = await request_engine.execute(verify_spec)
            if verify_resp.success and verify_resp.response_status == 200:
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=target_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.MEDIUM,
                    candidate_reason=f"Session token remained active and returned HTTP 200 after explicit logout via '{logout_url}'.",
                    request_ids=[logout_resp.request_id, verify_resp.request_id],
                    evidence_ids=[logout_resp.evidence_id, verify_resp.evidence_id],
                    observed_data={
                        "logout_url": logout_url,
                        "logout_status": logout_resp.response_status,
                        "post_logout_status": verify_resp.response_status,
                    },
                    payload="Session Replay Post-Logout",
                    proof_response=f"Logout: HTTP {logout_resp.response_status} -> Subsequent Protected Request: HTTP {verify_resp.response_status}",
                    confidence=85,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C018SessionInvalidation)
