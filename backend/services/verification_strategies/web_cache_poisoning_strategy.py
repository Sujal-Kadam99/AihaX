"""Deterministic Verification Strategy for Web Cache Poisoning / Cache Deception (C079)."""

from __future__ import annotations

from typing import Any, Dict, Optional
import uuid

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


class WebCachePoisoningVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies Web Cache Poisoning by executing a two-phase test:
    1. Poisoning Request: Sends an unkeyed header (e.g. X-Forwarded-Host) with a unique canary.
    2. Clean Victim Request: Issues a subsequent clean request to the exact same cache key URL.
    Confirms vulnerability only if the second (clean) response serves the cached poisoned content.
    """

    contract = VerificationContract(
        check_id="C079_Web_Cache_Poisoning",
        name="Web Cache Poisoning Verification",
        security_property="Cached responses must not serve content influenced by unkeyed request headers.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url

        if context.budget.max_requests < 2:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description="Insufficient request budget for two-phase cache poisoning verification.",
            )

        token = uuid.uuid4().hex[:8]
        canary_host = f"aihax-poison-canary-{token}.test"
        cache_buster = f"aihax_cb={token}"
        separator = "&" if "?" in affected_url else "?"
        test_url = f"{affected_url}{separator}{cache_buster}"

        # Phase 1: Poisoning attempt
        poison_spec = RequestSpec(
            url=test_url,
            method="GET",
            headers={"X-Forwarded-Host": canary_host},
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        try:
            resp1 = await context.send_verification_request(poison_spec)
        except Exception as exc:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description=f"Cache poisoning probe failed: {exc}",
            )

        resp1_body = resp1.response_body or ""
        # If the unkeyed header wasn't even reflected in phase 1, cannot poison
        if canary_host not in resp1_body and canary_host not in str(resp1.response_headers):
            ev_id = context.record_evidence(
                evidence_type="cache_poison_not_reflected",
                data={"status": resp1.response_status},
                request_id=resp1.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
                reason_description="Unkeyed header was not reflected in the server response.",
                evidence_ids=[ev_id],
                request_ids=[resp1.request_id],
                confidence=95,
            )

        # Phase 2: Clean victim request
        clean_spec = RequestSpec(
            url=test_url,
            method="GET",
            headers={},  # Clean request without X-Forwarded-Host
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        try:
            resp2 = await context.send_verification_request(clean_spec)
        except Exception as exc:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description=f"Clean victim request failed: {exc}",
            )

        resp2_body = resp2.response_body or ""
        ev_id = context.record_evidence(
            evidence_type="cache_poison_verification",
            data={
                "resp1_status": resp1.response_status,
                "resp2_status": resp2.response_status,
                "canary_in_resp2": canary_host in resp2_body or canary_host in str(resp2.response_headers),
            },
            request_id=resp2.request_id,
        )

        # If the clean victim response also contains the poisoned canary -> Proven!
        if canary_host in resp2_body or canary_host in str(resp2.response_headers):
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description="Web Cache Poisoning confirmed: Subsequent clean request was served poisoned cached response.",
                evidence_ids=[ev_id],
                request_ids=[resp1.request_id, resp2.request_id],
                confidence=100,
            )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description="Response reflects unkeyed header but is not cached or served to unpoisoned requests.",
            evidence_ids=[ev_id],
            request_ids=[resp1.request_id, resp2.request_id],
            confidence=90,
        )


# Register strategy
VerificationRegistry.register(WebCachePoisoningVerificationStrategy)
