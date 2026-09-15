"""Mass Assignment Verification Strategy."""
import json
from backend.services.verification_engine import (
    VerificationStatus,
    VerificationReasonCode,
    VerificationConclusion,
    BaseVerificationStrategy,
    VerificationContext,
    VerificationContract,
)
from backend.services.request_engine import RequestSpec, RequestTimeout

class MassAssignmentVerificationStrategy(BaseVerificationStrategy):
    contract = VerificationContract(
        check_id="C070_Mass_Assignment",
        name="Mass Assignment Verification (Dedicated)",
        security_property="Data transfer models must not bind client-supplied privileged properties",
        required_evidence_fields=["payload"],
        destructive=False,
    )

    async def verify(self, ctx: VerificationContext) -> VerificationConclusion:
        if not ctx.candidate_evidence.get("payload"):
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                reason_description="No payload provided in candidate evidence",
                confidence=0
            )

        target_url = ctx.target_url
        try:
            malicious_payload = json.loads(ctx.candidate_evidence["payload"])
        except json.JSONDecodeError:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                reason_description="Payload is not valid JSON",
                confidence=0
            )

        privileged_keys = {"is_admin", "role", "admin"}
        baseline_payload = {k: v for k, v in malicious_payload.items() if k not in privileged_keys}

        # 1. Baseline Request
        baseline_spec = RequestSpec(
            url=target_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps(baseline_payload),
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        baseline_resp = await ctx.send_verification_request(baseline_spec)
        ctx.record_evidence("BASELINE_RESPONSE", {"status": baseline_resp.response_status}, baseline_resp.request_id)

        if not baseline_resp.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description="Baseline request failed",
                confidence=0
            )

        # 2. Malicious Request
        malicious_spec = RequestSpec(
            url=target_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps(malicious_payload),
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        malicious_resp = await ctx.send_verification_request(malicious_spec)
        ctx.record_evidence("MALICIOUS_RESPONSE", {"status": malicious_resp.response_status}, malicious_resp.request_id)

        if not malicious_resp.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description="Malicious request failed",
                confidence=0
            )

        baseline_body = (baseline_resp.response_body or "").lower()
        malicious_body = (malicious_resp.response_body or "").lower()

        privileged_indicators = ['"is_admin":true', '"is_admin": true', '"role":"admin"', '"role": "admin"']
        baseline_has_privs = any(ind in baseline_body for ind in privileged_indicators)
        malicious_has_privs = any(ind in malicious_body for ind in privileged_indicators)

        if malicious_has_privs and not baseline_has_privs:
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description="Privileged properties were accepted and bound ONLY when explicitly supplied.",
                confidence=95,
                evidence_ids=[ev.evidence_id for ev in ctx.collected_evidence],
                request_ids=[baseline_resp.request_id, malicious_resp.request_id]
            )

        if baseline_has_privs and malicious_has_privs:
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
                reason_description="Privileged properties reflected even in baseline (likely default state, not mass assignment).",
                confidence=85
            )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTROL_ENFORCED,
            reason_description="Privileged properties were not bound.",
            confidence=90
        )
