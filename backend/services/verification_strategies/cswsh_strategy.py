"""Deterministic Verification Strategy for Cross-Site WebSocket Hijacking (C080)."""

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


class CswshVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies Cross-Site WebSocket Hijacking (CSWSH) by attempting a WebSocket handshake
    with an attacker-controlled Origin header. Confirms whether the server accepts
    unauthorized cross-origin connections (101 Switching Protocols) or enforces origin controls.
    """

    contract = VerificationContract(
        check_id="C080_Cross_Site_WebSocket_Hijacking",
        name="Cross-Site WebSocket Hijacking Verification",
        security_property="WebSocket handshake must reject untrusted cross-origin connections.",
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

        malicious_origin = "https://unauthorized-cross-origin.test"
        handshake_spec = RequestSpec(
            url=affected_url,
            method="GET",
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
                "Origin": malicious_origin,
            },
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        try:
            resp = await context.send_verification_request(handshake_spec)
        except Exception as exc:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description=f"WebSocket handshake failed: {exc}",
            )

        status = resp.response_status
        headers_lower = {k.lower(): v for k, v in resp.response_headers.items()}
        upgrade_hdr = headers_lower.get("upgrade", "").lower()

        ev_id = context.record_evidence(
            evidence_type="cswsh_handshake_attempt",
            data={
                "status": status,
                "origin": malicious_origin,
                "upgrade": upgrade_hdr,
                "sec_websocket_accept": headers_lower.get("sec-websocket-accept"),
            },
            request_id=resp.request_id,
        )

        # Server rejected handshake (e.g. 403 Forbidden, 401 Unauthorized, 400 Bad Request)
        if status in (400, 401, 403):
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.CONTROL_ENFORCED,
                reason_description=f"Server properly rejected unauthorized Origin with HTTP {status}.",
                evidence_ids=[ev_id],
                request_ids=[resp.request_id],
                confidence=95,
            )

        # Server accepted cross-origin handshake (101 Switching Protocols or WebSocket upgrade accepted)
        if status == 101 or "websocket" in upgrade_hdr:
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description=f"Cross-Site WebSocket Hijacking confirmed: Server accepted WebSocket handshake from untrusted Origin ({malicious_origin}).",
                evidence_ids=[ev_id],
                request_ids=[resp.request_id],
                confidence=95,
            )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description="Endpoint does not support WebSocket upgrade or rejected the protocol switch.",
            evidence_ids=[ev_id],
            request_ids=[resp.request_id],
            confidence=90,
        )


# Register strategy
VerificationRegistry.register(CswshVerificationStrategy)
