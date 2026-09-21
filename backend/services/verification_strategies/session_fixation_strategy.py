"""Verification strategy for C017: Session Fixation Indicators."""

from __future__ import annotations

import secrets
from backend.services.verification_engine import (
    BaseVerificationStrategy,
    VerificationConclusion,
    VerificationContext,
    VerificationContract,
    VerificationReasonCode,
    VerificationRegistry,
    VerificationStatus,
)
from backend.services.request_engine import RequestSpec, RequestTimeout


class SessionFixationVerificationStrategy(BaseVerificationStrategy):
    """Verifies whether an application allows client-specified or URL-supplied session tokens to be adopted."""

    contract = VerificationContract(
        check_id="C017_Session_Fixation",
        name="Session Fixation Verification",
        security_property="Applications must generate a fresh session identifier on authentication and reject client-supplied session adoption.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        url = context.candidate_evidence.get("affected_url") or context.target_url
        probe_token = f"aihax_fixed_token_{secrets.token_hex(4)}"

        sep = "&" if "?" in url else "?"
        probe_url = f"{url}{sep}sessionid={probe_token}&PHPSESSID={probe_token}&JSESSIONID={probe_token}"

        spec = RequestSpec(
            url=probe_url,
            method="GET",
            headers={"Cookie": f"sessionid={probe_token}"},
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        resp = await context.send_verification_request(spec)
        if not resp or not resp.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.TARGET_UNREACHABLE,
                reason_description="Target unreachable during session fixation verification probe.",
            )

        # Inspect response headers for adoption of the supplied token in Set-Cookie
        adopted = False
        adopted_header = ""
        for k, v in resp.response_headers.items():
            if k.lower() == "set-cookie":
                if probe_token in v:
                    adopted = True
                    adopted_header = v
                    break

        # Also check if response body acknowledges session token adoption
        if not adopted and probe_token in (resp.response_body or ""):
            # Only count body if it's not simply reflected input text in an echo
            if f'"sessionid":"{probe_token}"' in (resp.response_body or "") or f"'sessionid': '{probe_token}'" in (resp.response_body or ""):
                adopted = True
                adopted_header = "Response body JSON session object"

        if adopted:
            ev_id = context.record_evidence(
                evidence_type="session_fixation_token_adopted",
                data={
                    "probe_token": probe_token,
                    "evidence_header": adopted_header,
                    "status_code": resp.response_status,
                },
                request_id=resp.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description=f"Server adopted client-supplied fixed session token '{probe_token}' without regeneration.",
                evidence_ids=[ev_id],
                request_ids=[resp.request_id],
                confidence=90,
            )

        ev_id = context.record_evidence(
            evidence_type="session_fixation_negative_control",
            data={"status": "not_adopted"},
            request_id=resp.request_id,
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTROL_ENFORCED,
            reason_description="Server did not adopt client-supplied session token in Set-Cookie or session state.",
            evidence_ids=[ev_id],
            request_ids=[resp.request_id],
            confidence=85,
        )


VerificationRegistry.register(SessionFixationVerificationStrategy)
