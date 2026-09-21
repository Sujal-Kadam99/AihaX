"""Deterministic Verification Strategy for Missing OAuth state Parameter (C085)."""

from __future__ import annotations

from typing import Any, Dict, Optional
import urllib.parse

from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout
from backend.services.verification_engine import (
    BaseVerificationStrategy,
    VerificationBudget,
    VerificationConclusion,
    VerificationContext,
    VerificationContract,
    VerificationReasonCode,
    VerificationStatus,
    VerificationRegistry,
)


class OAuthStateParameterVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies Missing OAuth state Parameter (CSRF on OAuth flow) by issuing an authorization
    request without a state parameter and testing whether the authorization server
    allows completing the flow or mandates state validation.
    """

    contract = VerificationContract(
        check_id="C085_Missing_OAuth_State_Parameter",
        name="Missing OAuth state Parameter Verification",
        security_property="OAuth authorization server must mandate and validate session-bound state parameters.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url

        if context.budget.max_requests <= 0:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description="Verification budget exhausted.",
            )

        # Ensure state is omitted from URL
        parsed = urllib.parse.urlparse(affected_url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if "state" in params:
            del params["state"]

        test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(params, doseq=True)))

        spec = RequestSpec(
            url=test_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        try:
            resp = await context.send_verification_request(spec)
        except Exception as exc:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description=f"OAuth state parameter probe failed: {exc}",
            )

        status = resp.response_status
        location = resp.response_headers.get("location", "")
        body = resp.response_body or ""

        ev_id = context.record_evidence(
            evidence_type="oauth_state_probe",
            data={"status": status, "location": location},
            request_id=resp.request_id,
        )

        # Server requires state parameter (e.g. 400 Bad Request, missing state error)
        if (
            status in (400, 403)
            or "missing state" in body.lower()
            or "invalid state" in body.lower()
            or "state parameter is required" in body.lower()
            or "missing_state" in location.lower()
        ):
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.CONTROL_ENFORCED,
                reason_description="OAuth server properly enforced anti-CSRF state parameter presence.",
                evidence_ids=[ev_id],
                request_ids=[resp.request_id],
                confidence=95,
            )

        # Server proceeded without state
        if status in (200, 302):
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description="Missing OAuth state Parameter confirmed: Authorization flow can be initiated without anti-CSRF state protection.",
                evidence_ids=[ev_id],
                request_ids=[resp.request_id],
                confidence=90,
            )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description="OAuth endpoint did not complete authorization without state parameter.",
            evidence_ids=[ev_id],
            request_ids=[resp.request_id],
            confidence=85,
        )


# Register strategy
VerificationRegistry.register(OAuthStateParameterVerificationStrategy)
