from backend.services.verification_engine import (
    VerificationStatus,
    VerificationReasonCode,
    VerificationConclusion,
    BaseVerificationStrategy,
    VerificationContext,
    VerificationContract,
)
from backend.services.verification_strategies.request_builder import build_injected_request
import re

class CsrfVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies CSRF vulnerabilities by stripping CSRF tokens from the proof request
    and replaying it to check if the state-changing action still succeeds.
    """
    
    contract = VerificationContract(
        check_id="C016_Missing_SameSite_Cookie",
        name="CSRF Verification",
        security_property="State-changing requests require a valid CSRF token.",
        required_evidence_fields=["proof_request", "proof_response"],
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

        proof_request = candidate.get("proof_request")
        if not proof_request:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                reason_description="No proof request provided.",
            )

        # Attempt to rebuild request exactly as it was, but without CSRF tokens.
        # We use build_injected_request to get a base RequestSpec, then modify it.
        injected_req = build_injected_request(candidate, "")
        if not injected_req:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                reason_description="Could not reconstruct proof request.",
            )
            
        # Strip common CSRF headers
        csrf_headers = ["x-csrf-token", "csrf-token", "x-xsrf-token"]
        injected_req.headers = {k: v for k, v in injected_req.headers.items() if k.lower() not in csrf_headers}
        
        # Strip CSRF tokens from form body if present
        if injected_req.body and isinstance(injected_req.body, str):
            injected_req.body = re.sub(r'(?:csrf|nonce|token|authenticity_token|_token)=[^&]+&?', '', injected_req.body, flags=re.IGNORECASE)
            injected_req.body = injected_req.body.rstrip('&')
            
        context.budget.max_requests -= 1
        response = await context.request_engine.execute(injected_req)
        
        ev_id = context.record_evidence(
            evidence_type="csrf_replay_attempt",
            data={"status": response.status_code},
            request_id=response.request_id,
        )

        # CSRF success is typically if the state-changing endpoint succeeds (e.g. 200, 302 with location, etc)
        # We compare to the baseline proof_response status
        proof_response = candidate.get("proof_response")
        proof_status = 200
        if isinstance(proof_response, str) and "status_code" in proof_response:
            try:
                import ast
                resp_meta = ast.literal_eval(proof_response)
                proof_status = resp_meta.get("status_code", 200)
            except Exception:
                pass

        if response.status_code == proof_status or response.status_code in (200, 302, 201, 204):
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
                reason_description="State-changing request succeeded without CSRF token.",
                evidence_ids=[ev_id],
                request_ids=[response.request_id],
                confidence=100,
            )
            
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description=f"Request failed without CSRF token (status {response.status_code}).",
            evidence_ids=[ev_id],
            request_ids=[response.request_id],
            confidence=100,
        )
