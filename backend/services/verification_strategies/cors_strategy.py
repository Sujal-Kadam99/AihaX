from backend.services.verification_engine import (
    VerificationStatus,
    VerificationReasonCode,
    VerificationConclusion,
    BaseVerificationStrategy,
    VerificationContext,
    VerificationContract,
)
from backend.services.verification_strategies.request_builder import build_injected_request

class CorsVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies CORS Misconfiguration by replaying the proof request with
    a malicious Origin header and checking for Access-Control-Allow-Origin reflection.
    """
    
    contract = VerificationContract(
        check_id="C004_CORS_Misconfiguration",
        name="CORS Misconfiguration Verification",
        security_property="Server must not reflect arbitrary Origins with credentials.",
        required_evidence_fields=["proof_request"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        if context.budget.max_requests <= 0:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description="Verification budget exhausted.",
            )

        malicious_origin = "https://malicious-aihax-test.com"
        injected_req = build_injected_request(candidate, "")
        if not injected_req:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                reason_description="Could not reconstruct proof request.",
            )

        # Inject malicious Origin
        injected_req.headers["Origin"] = malicious_origin
        
        context.budget.max_requests -= 1
        response = await context.request_engine.execute(injected_req)
        
        ev_id = context.record_evidence(
            evidence_type="cors_replay_attempt",
            data={
                "status": response.status_code,
                "acao": response.response_headers.get("Access-Control-Allow-Origin"),
                "acac": response.response_headers.get("Access-Control-Allow-Credentials")
            },
            request_id=response.request_id,
        )

        acao = response.response_headers.get("Access-Control-Allow-Origin", "")
        acac = response.response_headers.get("Access-Control-Allow-Credentials", "false").lower()

        if acao == malicious_origin or acao == "*":
            if acac == "true":
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
                    reason_description=f"Server reflects arbitrary Origin ({malicious_origin}) with Credentials allowed.",
                    evidence_ids=[ev_id],
                    request_ids=[response.request_id],
                    confidence=100,
                )
            else:
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
                    reason_description=f"Server reflects arbitrary Origin ({malicious_origin}) without Credentials.",
                    evidence_ids=[ev_id],
                    request_ids=[response.request_id],
                    confidence=80,
                )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description="Server did not reflect the malicious Origin.",
            evidence_ids=[ev_id],
            request_ids=[response.request_id],
            confidence=100,
        )
