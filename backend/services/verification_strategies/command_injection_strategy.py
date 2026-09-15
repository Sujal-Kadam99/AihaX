import re
from backend.services.verification_engine import (
    BaseVerificationStrategy,
    VerificationContract,
    VerificationConclusion,
    VerificationContext,
    VerificationStatus,
    VerificationReasonCode,
)
from backend.services.request_engine import RequestSpec
from backend.services.verification_strategies.request_builder import build_injected_request

class CommandInjectionVerificationStrategy(BaseVerificationStrategy):
    contract = VerificationContract(
        check_id="C026_OS_Command_Injection",
        name="OS Command Injection Verification",
        security_property="Target reflects output of injected OS commands (e.g., uid/gid).",
        required_evidence_fields=["affected_url", "proof_request"],
        destructive=False,
    )

    MARKERS = [
        re.compile(r"uid=\d+\([\w-]+\)\s+gid=\d+\([\w-]+\)"),
        re.compile(r"uid=\d+\s+gid=\d+"),
        re.compile(r"root:x:0:0:"),
        re.compile(r"Windows IP Configuration", re.IGNORECASE),
        re.compile(r"Directory of [a-zA-Z]:\\", re.IGNORECASE),
    ]

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        
        # 1. Baseline Request
        # Use an empty/benign payload to check if the marker appears naturally.
        spec_baseline = build_injected_request(candidate, "127.0.0.1")
        if not spec_baseline:
            ev_id = context.record_evidence(
                evidence_type="missing_evidence",
                data={"reason": "Could not parse injection point or missing proof_request."}
            )
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                reason_description="Candidate finding lacks mandatory proof_request or affected_url.",
                evidence_ids=[ev_id],
                confidence=0,
            )
            


        try:
            baseline_res = await context.send_verification_request(spec_baseline)
        except Exception as e:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description=f"Baseline request failed: {e}",
                confidence=0,
            )

        baseline_body = (baseline_res.response_body or "")

        # 2. Test Request (replay malicious payload)
        payload = candidate.get("payload", "")
        spec_test = build_injected_request(candidate, payload)
        if not spec_test:
             return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                reason_description="Could not rebuild test request.",
                confidence=0,
            )


        try:
            test_res = await context.send_verification_request(spec_test)
        except Exception as e:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description=f"Test request failed: {e}",
                confidence=0,
            )
            
        test_body = (test_res.response_body or "")

        # 3. Validation Logic
        reproduced = False
        contradiction = False
        
        for marker_regex in self.MARKERS:
            # If marker is found in test...
            if marker_regex.search(test_body):
                # ...but also in baseline, it's a contradiction/false positive
                if marker_regex.search(baseline_body):
                    contradiction = True
                else:
                    reproduced = True
                    break

        if contradiction and not reproduced:
            ev_id = context.record_evidence(
                evidence_type="contradictory_evidence",
                data={"reason": "Command output marker found in baseline response."}
            )
            return VerificationConclusion(
                status=VerificationStatus.REJECTED,
                reason_code=VerificationReasonCode.INCONSISTENT_BEHAVIOR,
                reason_description="Command output was found in the benign baseline request.",
                evidence_ids=[ev_id],
                confidence=95,
            )

        if reproduced:
            ev_id = context.record_evidence(
                evidence_type="test_verification",
                data={"reason": "Command output marker found exclusively in test response."}
            )
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
                reason_description="Command output was deterministically replicated on target endpoint.",
                evidence_ids=[ev_id],
                confidence=100,
            )

        # Did not find any markers
        ev_id = context.record_evidence(
            evidence_type="failed_verification",
            data={"reason": "Command output markers not found in test response."}
        )
        return VerificationConclusion(
            status=VerificationStatus.INCONCLUSIVE,
            reason_code=VerificationReasonCode.INCONSISTENT_BEHAVIOR,
            reason_description="Candidate proof could not be reproduced on target response.",
            evidence_ids=[ev_id],
            confidence=30,
        )
