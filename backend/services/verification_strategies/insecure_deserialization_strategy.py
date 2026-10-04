"""Deterministic Verification Strategy for Insecure Deserialization (C086)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout
from backend.services.verification_engine import (
    BaseVerificationStrategy,
    VerificationBudget,
    VerificationConclusion,
    VerificationContext,
    VerificationContract,
    VerificationReasonCode,
    VerificationStatus,
    VerificationRegistry,
)


class InsecureDeserializationVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies Insecure Deserialization by sending non-destructive structured serialized canary
    probes and observing whether the server actively deserializes and instantiates objects.
    """

    contract = VerificationContract(
        check_id="C086_Insecure_Deserialization_Indicators",
        name="Insecure Deserialization Verification",
        security_property="Server must not instantiate untrusted serialized object streams.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url

        if context.budget.max_requests <= 0:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description="Verification budget exhausted.",
            )

        # Benign non-destructive serialized canary object probe
        php_canary = 'O:8:"stdClass":1:{s:13:"aihax_canary";s:8:"verified";}'
        spec = RequestSpec(
            url=affected_url,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=f"data={php_canary}",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        try:
            resp = await context.send_verification_request(spec)
        except Exception as exc:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description=f"Deserialization verification probe failed: {exc}",
            )

        status = resp.response_status
        body = resp.response_body or ""

        ev_id = context.record_evidence(
            evidence_type="deserialization_probe",
            data={"status": status, "body": body[:300]},
            request_id=resp.request_id,
        )

        # Server rejected content type or media with 415 or cleanly validated input
        if status in (415, 400) and not any(k in body.lower() for k in ["unserialize", "unpickl", "deserializ"]):
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.CONTROL_ENFORCED,
                reason_description="Server rejected serialized input and did not execute deserializer.",
                evidence_ids=[ev_id],
                request_ids=[resp.request_id],
                confidence=95,
            )

        # Evidence of active deserialization
        deserialization_signatures = [
            "unserialize()",
            "java.io.InvalidClassException",
            "java.io.StreamCorruptedException",
            "java.io.ObjectInputStream",
            "UnpicklingError",
            "pickle.Unpickler",
            "BinaryFormatter",
            "TypeNameHandling",
            "aihax_canary",
        ]

        if any(sig.lower() in body.lower() for sig in deserialization_signatures) or (status == 200 and "verified" in body):
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description="Insecure Deserialization confirmed: Server accepted and processed untrusted serialized object payload.",
                evidence_ids=[ev_id],
                request_ids=[resp.request_id],
                confidence=95,
            )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description="Server did not deserialize or execute the serialized probe.",
            evidence_ids=[ev_id],
            request_ids=[resp.request_id],
            confidence=90,
        )


# Register strategy
VerificationRegistry.register(InsecureDeserializationVerificationStrategy)
