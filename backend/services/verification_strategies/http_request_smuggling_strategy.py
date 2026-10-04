"""Deterministic Verification Strategy for HTTP Request Smuggling (C078)."""

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


class HttpRequestSmugglingVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies HTTP Request Smuggling (CL.TE / TE.CL Desync) by sending a bounded
    two-phase desync probe and checking whether a follow-up request exhibits a desynchronization
    side effect (e.g. smuggled prefix execution or desync-induced parsing failure)
    rather than a clean RFC-compliant 400 rejection.
    """

    contract = VerificationContract(
        check_id="C078_HTTP_Request_Smuggling",
        name="HTTP Request Smuggling Verification",
        security_property="HTTP proxies and origin servers must uniformly parse request lengths and reject dual framing.",
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
                reason_description="Insufficient request budget for request smuggling verification.",
            )

        # Phase 1: Send CL.TE desync request
        canary_smuggle_body = "0\r\n\r\nGET /aihax_smuggle_canary HTTP/1.1\r\nHost: aihax.test\r\nX-Ignore: X"
        smuggle_spec = RequestSpec(
            url=affected_url,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(canary_smuggle_body)),
                "Transfer-Encoding": "chunked",
            },
            body=canary_smuggle_body,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        try:
            resp1 = await context.send_verification_request(smuggle_spec)
        except Exception as exc:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description=f"Desync probe failed: {exc}",
            )

        # If front-end rejected immediately with 400 Bad Request
        if resp1.response_status in (400, 403, 405):
            ev_id = context.record_evidence(
                evidence_type="smuggling_rejected",
                data={"status": resp1.response_status, "body": (resp1.response_body or "")[:300]},
                request_id=resp1.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.CONTROL_ENFORCED,
                reason_description=f"Server properly rejected ambiguous CL/TE headers with HTTP {resp1.response_status}.",
                evidence_ids=[ev_id],
                request_ids=[resp1.request_id],
                confidence=95,
            )

        # Phase 2: Follow-up request to check pipeline desync
        followup_spec = RequestSpec(
            url=affected_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        try:
            resp2 = await context.send_verification_request(followup_spec)
        except Exception:
            resp2 = None

        ev_id = context.record_evidence(
            evidence_type="smuggling_probe_result",
            data={
                "resp1_status": resp1.response_status,
                "resp2_status": resp2.response_status if resp2 else None,
                "resp2_body": (resp2.response_body or "")[:300] if resp2 else None,
            },
            request_id=resp1.request_id,
        )

        # If desync caused observable backend anomaly (e.g. 404 on smuggled canary path, 500, or 502)
        if resp2 and (
            resp2.response_status in (404, 500, 502)
            or "/aihax_smuggle_canary" in (resp2.response_body or "")
        ):
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description="HTTP Request Smuggling confirmed: Ambiguous framing accepted and follow-up pipeline affected.",
                evidence_ids=[ev_id],
                request_ids=[resp1.request_id, resp2.request_id] if resp2 else [resp1.request_id],
                confidence=95,
            )

        # If dual headers were accepted on probe 1 without 400
        if resp1.response_status in (200, 201, 204):
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description="Ambiguous Content-Length and Transfer-Encoding headers accepted by HTTP frontend.",
                evidence_ids=[ev_id],
                request_ids=[resp1.request_id],
                confidence=85,
            )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description="No request desynchronization or pipeline poisoning observed.",
            evidence_ids=[ev_id],
            request_ids=[resp1.request_id],
            confidence=90,
        )


# Register strategy
VerificationRegistry.register(HttpRequestSmugglingVerificationStrategy)
