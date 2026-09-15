"""Race Condition Verification Strategy."""
import asyncio
from backend.services.verification_engine import (
    VerificationStatus,
    VerificationReasonCode,
    VerificationConclusion,
    BaseVerificationStrategy,
    VerificationContext,
    VerificationContract,
)
from backend.services.request_engine import RequestSpec, RequestTimeout

class RaceConditionVerificationStrategy(BaseVerificationStrategy):
    contract = VerificationContract(
        check_id="C075_Race_Condition",
        name="Race Condition Verification (Dedicated)",
        security_property="Critical state-modifying actions must enforce transaction isolation",
        required_evidence_fields=["payload"],
        destructive=False,
    )

    async def verify(self, ctx: VerificationContext) -> VerificationConclusion:
        # Check if the safeguard flag was passed in candidate evidence by the check
        permit_testing = ctx.candidate_evidence.get("observed_data", {}).get("permit_race_condition_testing", False)
        
        if not permit_testing:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.OUT_OF_SCOPE_BLOCKED,
                reason_description="Race condition testing safeguard enabled (permit_race_condition_testing=False).",
                confidence=0
            )

        target_url = ctx.target_url
        if not target_url:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                reason_description="No target URL provided",
                confidence=0
            )

        # Fire 5 concurrent requests
        specs = [
            RequestSpec(
                url=target_url,
                method="POST",
                headers={"Content-Type": "application/json", "X-Concurrency-Probe": f"verify_{i}"},
                body='{"action": "verify", "token": "aihax_concurrency_verification_123"}',
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            for i in range(5)
        ]

        responses = await asyncio.gather(*[ctx.send_verification_request(s) for s in specs], return_exceptions=True)
        
        successful_resps = []
        for r in responses:
            if not isinstance(r, Exception):
                ctx.record_evidence("CONCURRENT_RESPONSE", {"status": r.response_status}, r.request_id)
                if r.success and r.response_status in (200, 201):
                    successful_resps.append(r)

        if len(successful_resps) >= 2:
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description=f"{len(successful_resps)} concurrent requests executed with status 200/201.",
                confidence=95,
                evidence_ids=[ev.evidence_id for ev in ctx.collected_evidence],
                request_ids=[r.request_id for r in successful_resps]
            )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTROL_ENFORCED,
            reason_description="Concurrency locking prevented multiple successful executions.",
            confidence=90
        )
