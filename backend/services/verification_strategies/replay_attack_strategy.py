"""Verification strategy for C076: Replay Attack Vulnerability."""

from __future__ import annotations

import json
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


class ReplayAttackVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies transaction replay attack vulnerabilities by submitting identical single-use payloads
    or transactional requests twice in succession to observe if nonce/one-time token consumption is enforced.
    """

    contract = VerificationContract(
        check_id="C076_Replay_Attack",
        name="Replay Attack Verification",
        security_property="Transactional and single-use action endpoints must enforce replay prevention via nonce consumption or immediate token invalidation.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        url = context.candidate_evidence.get("affected_url") or context.target_url
        nonce = f"aihax_nonce_{secrets.token_hex(4)}"
        payload = json.dumps({"otp": "123456", "nonce": nonce, "transaction_id": f"tx_{secrets.token_hex(4)}"})

        spec1 = RequestSpec(
            url=url,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=payload,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp1 = await context.send_verification_request(spec1)
        if not resp1 or not resp1.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.TARGET_UNREACHABLE,
                reason_description="Target unreachable during replay attack verification initial probe.",
            )

        # If the first request was rejected as invalid syntax/not found, cannot test replay reliably
        if resp1.response_status not in (200, 201):
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.CONTROL_ENFORCED,
                reason_description="Initial request was rejected; cannot demonstrate replay vulnerability.",
                request_ids=[resp1.request_id],
                confidence=80,
            )

        # Replay identical payload
        spec2 = RequestSpec(
            url=url,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=payload,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp2 = await context.send_verification_request(spec2)
        if not resp2 or not resp2.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.TARGET_UNREACHABLE,
                reason_description="Target unreachable during replayed verification probe.",
                request_ids=[resp1.request_id],
            )

        # If the second replayed request succeeds identically
        if resp2.response_status == resp1.response_status and resp2.response_status in (200, 201):
            ev_id = context.record_evidence(
                evidence_type="replay_attack_demonstrated",
                data={
                    "url": url,
                    "first_status": resp1.response_status,
                    "replayed_status": resp2.response_status,
                    "nonce": nonce,
                },
                request_id=resp2.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description=f"Action accepted replayed single-use transaction payload twice with identical HTTP {resp2.response_status}.",
                evidence_ids=[ev_id],
                request_ids=[resp1.request_id, resp2.request_id],
                confidence=85,
            )

        ev_id = context.record_evidence(
            evidence_type="replay_prevented",
            data={
                "first_status": resp1.response_status,
                "replayed_status": resp2.response_status,
            },
            request_id=resp2.request_id,
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTROL_ENFORCED,
            reason_description=f"Replayed transaction was rejected with HTTP {resp2.response_status}.",
            evidence_ids=[ev_id],
            request_ids=[resp1.request_id, resp2.request_id],
            confidence=85,
        )


VerificationRegistry.register(ReplayAttackVerificationStrategy)
