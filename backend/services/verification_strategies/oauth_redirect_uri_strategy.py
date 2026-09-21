"""Deterministic Verification Strategy for OAuth Redirect URI Validation (C084)."""

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


class OAuthRedirectUriVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies OAuth/SSO Redirect URI Validation Weakness by injecting an unauthorized
    canary redirect_uri parameter and checking if the authorization server redirects to it
    or accepts the parameter without validation error.
    """

    contract = VerificationContract(
        check_id="C084_OAuth_Redirect_URI_Validation",
        name="OAuth Redirect URI Validation Verification",
        security_property="OAuth authorization servers must reject un-whitelisted redirect_uri values.",
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

        canary_redirect = "https://aihax-oauth-canary.test/callback"
        parsed = urllib.parse.urlparse(affected_url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params["redirect_uri"] = [canary_redirect]
        if "client_id" not in params:
            params["client_id"] = ["aihax_client_probe"]
        if "response_type" not in params:
            params["response_type"] = ["code"]

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
                reason_description=f"OAuth verification request failed: {exc}",
            )

        status = resp.response_status
        headers_lower = {k.lower(): v for k, v in resp.response_headers.items()}
        location = headers_lower.get("location", "")
        body = resp.response_body or ""

        ev_id = context.record_evidence(
            evidence_type="oauth_redirect_validation_probe",
            data={
                "status": status,
                "location": location,
                "canary_redirect": canary_redirect,
            },
            request_id=resp.request_id,
        )

        # Server rejected the untrusted redirect_uri
        if (
            status in (400, 403)
            or "invalid_redirect_uri" in location.lower()
            or "invalid_redirect" in body.lower()
            or "redirect_uri mismatch" in body.lower()
            or "unauthorized redirect_uri" in body.lower()
        ):
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.CONTROL_ENFORCED,
                reason_description="OAuth server properly validated redirect_uri and rejected untrusted callback destination.",
                evidence_ids=[ev_id],
                request_ids=[resp.request_id],
                confidence=95,
            )

        # Server issued redirect to canary or accepted parameter
        if canary_redirect in location:
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description=f"OAuth Redirect URI Validation Weakness confirmed: Server issued redirect to untrusted target ({canary_redirect}).",
                evidence_ids=[ev_id],
                request_ids=[resp.request_id],
                confidence=100,
            )

        if status == 200 and ("consent" in body.lower() or "authorize" in body.lower() or "allow" in body.lower()):
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description="OAuth server accepted untrusted redirect_uri and proceeded to authorization prompt.",
                evidence_ids=[ev_id],
                request_ids=[resp.request_id],
                confidence=85,
            )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description="OAuth endpoint did not accept or redirect to the untrusted redirect_uri.",
            evidence_ids=[ev_id],
            request_ids=[resp.request_id],
            confidence=90,
        )


# Register strategy
VerificationRegistry.register(OAuthRedirectUriVerificationStrategy)
