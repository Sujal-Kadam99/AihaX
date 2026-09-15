"""Default Credentials Verification Strategy.

Tries a small fixed list of well-known default credential pairs against
a login endpoint and checks for successful authentication responses.
"""

from backend.services.verification_engine import (
    VerificationStatus,
    VerificationReasonCode,
    VerificationConclusion,
    BaseVerificationStrategy,
    VerificationContext,
    VerificationContract,
)
from backend.services.request_engine import RequestSpec, RequestTimeout


class DefaultCredentialsVerificationStrategy(BaseVerificationStrategy):
    """
    Dedicated verification strategy for C022/C012 Default Credentials findings.

    Tries max 5 well-known default credential pairs against the login endpoint.
    Checks response for successful auth indicators (200 + "dashboard"/"welcome",
    302 redirect to authenticated area, session cookie set).

    SAFETY: Limited to 5 attempts max. Uses only well-known default pairs.
    Non-destructive: does not create accounts or modify state.
    """

    contract = VerificationContract(
        check_id="C012_Default_Credentials",
        name="Default Credentials Verification",
        security_property="Application must not accept well-known default credential pairs.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    # Well-known default credential pairs (max 5, non-destructive)
    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
        ("admin", "123456"),
        ("admin", "admin123"),
    ]

    # Success indicators in response body
    AUTH_SUCCESS_INDICATORS = [
        "dashboard", "welcome", "logged in", "logout", "my account",
        "profile", "successfully", "session", "authenticated",
    ]

    # Common login form field names
    USERNAME_FIELDS = ["username", "user", "login", "email", "user_login"]
    PASSWORD_FIELDS = ["password", "pass", "pwd", "passwd", "user_password"]

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        if context.budget.max_requests <= 0:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description="Verification budget exhausted.",
            )

        affected_url = candidate.get("affected_url") or context.target_url

        # Determine field names from candidate evidence or use defaults
        username_field = candidate.get("username_field", "username")
        password_field = candidate.get("password_field", "password")

        for username, password in self.DEFAULT_CREDS:
            if context.budget.max_requests <= 0:
                break

            body = f"{username_field}={username}&{password_field}={password}"
            spec = RequestSpec(
                url=affected_url,
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=body,
                follow_redirects=True,
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )

            context.budget.max_requests -= 1
            response = await context.request_engine.execute(spec)

            if not response.success:
                continue

            resp_body_lower = (response.response_body or "").lower()
            resp_status = response.response_status
            resp_headers = response.response_headers

            # Check for auth success: 200/302 + success indicators in body
            has_success_indicator = any(
                ind in resp_body_lower for ind in self.AUTH_SUCCESS_INDICATORS
            )
            # Check for session cookie being set
            has_session_cookie = any(
                "set-cookie" in k.lower() for k in resp_headers.keys()
            )
            # Check for redirect to authenticated area (not back to login)
            is_auth_redirect = (
                resp_status in (200, 302, 303)
                and "login" not in resp_body_lower[:500]
                and (has_success_indicator or has_session_cookie)
            )

            if has_success_indicator or is_auth_redirect:
                ev_id = context.record_evidence(
                    evidence_type="default_credentials_verified",
                    data={
                        "username": username,
                        "password": "***REDACTED***",
                        "status": resp_status,
                        "has_success_indicator": has_success_indicator,
                        "has_session_cookie": has_session_cookie,
                        "body_snippet": resp_body_lower[:200],
                    },
                    request_id=response.request_id,
                )

                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
                    reason_description=(
                        f"Default credentials accepted: username='{username}' with a "
                        f"well-known default password. HTTP {resp_status} with auth "
                        f"success indicators detected."
                    ),
                    evidence_ids=[ev_id],
                    request_ids=[response.request_id],
                    confidence=95,
                )

        # None of the default credentials worked
        ev_id = context.record_evidence(
            evidence_type="default_credentials_rejected",
            data={"pairs_tested": len(self.DEFAULT_CREDS)},
            request_id="N/A",
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description=f"None of {len(self.DEFAULT_CREDS)} default credential pairs were accepted.",
            evidence_ids=[ev_id],
            confidence=100,
        )
