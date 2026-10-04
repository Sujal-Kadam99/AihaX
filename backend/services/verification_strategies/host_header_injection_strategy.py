"""Deterministic Verification Strategy for Host Header Injection (C081)."""

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


class HostHeaderInjectionVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies Host Header Injection by injecting a unique canary Host / X-Forwarded-Host
    and confirming whether the untrusted host is reflected into actionable security contexts:
    - Absolute password-reset URLs or action targets
    - Absolute redirect Location headers
    - Script/link/form inclusion URLs
    """

    contract = VerificationContract(
        check_id="C081_Host_Header_Injection",
        name="Host Header Injection Verification",
        security_property="Web application must not generate security-sensitive URLs or redirects from untrusted Host headers.",
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

        token = uuid.uuid4().hex[:8]
        canary_host = f"aihax-injected-host-{token}.test"

        spec = RequestSpec(
            url=affected_url,
            method="GET",
            headers={"Host": canary_host, "X-Forwarded-Host": canary_host},
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        try:
            resp = await context.send_verification_request(spec)
        except Exception as exc:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description=f"Host header injection probe failed: {exc}",
            )

        status = resp.response_status
        headers_lower = {k.lower(): v for k, v in resp.response_headers.items()}
        location = headers_lower.get("location", "")
        body = resp.response_body or ""

        ev_id = context.record_evidence(
            evidence_type="host_header_replay",
            data={
                "status": status,
                "canary_host": canary_host,
                "location": location,
                "reflected_in_body": canary_host in body,
            },
            request_id=resp.request_id,
        )

        # Rejection via 400 Invalid Host or 403 Forbidden
        if status in (400, 403):
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.CONTROL_ENFORCED,
                reason_description=f"Server properly validated Host header and rejected untrusted host with HTTP {status}.",
                evidence_ids=[ev_id],
                request_ids=[resp.request_id],
                confidence=95,
            )

        # Check for actionable reflection contexts
        actionable_reflection = (
            canary_host in location
            or f"href=\"http://{canary_host}" in body
            or f"href=\"https://{canary_host}" in body
            or f"href=\"//{canary_host}" in body
            or f"action=\"http://{canary_host}" in body
            or f"action=\"https://{canary_host}" in body
            or f"src=\"http://{canary_host}" in body
            or f"src=\"https://{canary_host}" in body
        )

        if actionable_reflection:
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description=f"Host Header Injection confirmed: Injected host ({canary_host}) reflected into actionable URL/redirect context.",
                evidence_ids=[ev_id],
                request_ids=[resp.request_id],
                confidence=95,
            )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description="Injected Host header was not reflected in any actionable or security-sensitive URL context.",
            evidence_ids=[ev_id],
            request_ids=[resp.request_id],
            confidence=90,
        )


# Register strategy
VerificationRegistry.register(HostHeaderInjectionVerificationStrategy)
