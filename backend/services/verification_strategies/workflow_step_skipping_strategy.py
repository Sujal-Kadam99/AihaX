"""Verification strategy for C074: Step Skipping in Multi-Step Workflows."""

from __future__ import annotations

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


class WorkflowStepSkippingVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies multi-step workflow step skipping flaws by attempting to invoke finalization/completion
    endpoints directly without preceding prerequisite state or valid transaction progression.
    """

    contract = VerificationContract(
        check_id="C074_Workflow_Step_Skipping",
        name="Workflow Step Skipping Verification",
        security_property="Multi-step workflows must enforce sequential state progression and validate prerequisite stages.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        url = context.candidate_evidence.get("affected_url") or context.target_url

        # Attempt direct unauthenticated / un-progressed execution of final step
        spec = RequestSpec(
            url=url,
            method="POST",
            headers={"Content-Type": "application/json"},
            body="{}",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp = await context.send_verification_request(spec)
        if not resp or not resp.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.TARGET_UNREACHABLE,
                reason_description="Target unreachable during workflow step skipping verification probe.",
            )

        body_lower = (resp.response_body or "").lower()

        # If direct completion returned HTTP 200/201 and contains explicit confirmation / success indicators
        if resp.response_status in (200, 201) and ("success" in body_lower or "confirmed" in body_lower or "completed" in body_lower or "order_id" in body_lower):
            ev_id = context.record_evidence(
                evidence_type="workflow_step_skipped_success",
                data={
                    "endpoint": url,
                    "status_code": resp.response_status,
                    "response_preview": (resp.response_body or "")[:200],
                },
                request_id=resp.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description=f"Workflow completion endpoint '{url}' accepted direct execution (HTTP {resp.response_status}) without completing prerequisite stages.",
                evidence_ids=[ev_id],
                request_ids=[resp.request_id],
                confidence=85,
            )

        ev_id = context.record_evidence(
            evidence_type="workflow_state_enforced",
            data={"status_code": resp.response_status},
            request_id=resp.request_id,
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTROL_ENFORCED,
            reason_description="Server enforced workflow state progression and rejected direct completion invocation.",
            evidence_ids=[ev_id],
            request_ids=[resp.request_id],
            confidence=85,
        )


VerificationRegistry.register(WorkflowStepSkippingVerificationStrategy)
