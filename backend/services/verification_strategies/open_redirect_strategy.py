from backend.services.verification_engine import (
    VerificationStatus,
    VerificationReasonCode,
    VerificationConclusion,
    BaseVerificationStrategy,
    VerificationContext,
    VerificationContract,
)
from backend.services.verification_strategies.request_builder import build_injected_request


class OpenRedirectVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies Open Redirect vulnerabilities by replaying the exact proof_request
    and checking if the `Location` header matches the expected payload.
    """
    
    contract = VerificationContract(
        check_id="C007_Open_Redirect",
        name="Open Redirect Verification",
        security_property="Target redirects to an arbitrary external domain.",
        required_evidence_fields=["affected_url", "proof_request"],
        destructive=False,
    )

    TARGET_CHECK_IDS = ["C007_Open_Redirect", "C007"]

    async def verify(
        self, context: VerificationContext
    ) -> VerificationConclusion:
        candidate = context.candidate_evidence
        if context.budget.max_requests <= 0:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description="Verification budget exhausted.",
                evidence_ids=[candidate.get("id")] if candidate.get("id") else [],
            )

        payload = candidate.get("payload", "")
        # The payload might be URL encoded in the request, but we'll try to find it in the Location header
        injected_req = build_injected_request(candidate, payload)
        
        if not injected_req:
            # If we couldn't build it via parameters, fallback to exact proof_request replay
            # but request_builder handles this mostly. If it fails, we use a basic fallback.
            pass

        # We need the injected request to replay
        if not injected_req:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                reason_description="Could not reconstruct proof request.",
                evidence_ids=[candidate.get("id")] if candidate.get("id") else [],
            )

        # Do not follow redirects! We need to see the 30x response and Location header.
        injected_req.follow_redirects = False
        response = await context.request_engine.execute(injected_req)

        if not response:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description="Failed to get a response from the endpoint.",
                evidence_ids=[candidate.get("id")] if candidate.get("id") else [],
            )

        evidence_ids = []
        if candidate.get("id"):
            evidence_ids.append(candidate["id"])
        if response and hasattr(response, "evidence_id"):
            evidence_ids.append(response.evidence_id)

        # Check if the response is a redirect
        if response.status_code in [301, 302, 303, 307, 308]:
            location_header = response.response_headers.get("Location", "")
            if not location_header:
                location_header = response.response_headers.get("location", "")
                
            if payload and payload in location_header:
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
                    reason_description="Open redirect reproduced: Location header matches payload.",
                    evidence_ids=evidence_ids,
                    confidence=100,
                )
            else:
                return VerificationConclusion(
                    status=VerificationStatus.FALSE_POSITIVE,
                    reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
                    reason_description=f"Redirect occurred, but to '{location_header}' (did not match payload).",
                    evidence_ids=evidence_ids,
                    confidence=95,
                )
        else:
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
                reason_description=f"Expected redirect response (30x), got HTTP {response.status_code}.",
                evidence_ids=evidence_ids,
                confidence=95,
            )
