"""Verification strategy for C066: Cleartext Sensitive Storage Indicators."""

from __future__ import annotations

import re
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


class CleartextStorageVerificationStrategy(BaseVerificationStrategy):
    """Verifies whether client-side JavaScript stores sensitive tokens/secrets directly in localStorage or sessionStorage."""

    contract = VerificationContract(
        check_id="C066_Cleartext_Storage_Indicators",
        name="Cleartext Sensitive Storage Verification",
        security_property="Authentication tokens and credentials must be stored in HttpOnly cookies rather than client-accessible Web Storage.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    STORAGE_PATTERNS = [
        re.compile(r"localStorage\.setItem\s*\(\s*['\"](?:token|jwt|auth|access_token|bearer|password)['\"]", re.I),
        re.compile(r"sessionStorage\.setItem\s*\(\s*['\"](?:token|jwt|auth|access_token|bearer|password)['\"]", re.I),
    ]

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        url = context.candidate_evidence.get("affected_url") or context.target_url

        spec = RequestSpec(
            url=url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp = await context.send_verification_request(spec)
        if not resp or not resp.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.TARGET_UNREACHABLE,
                reason_description="Target unreachable during cleartext storage verification probe.",
            )

        body = resp.response_body or ""
        for pat in self.STORAGE_PATTERNS:
            match = pat.search(body)
            if match:
                snippet = body[max(0, match.start() - 10) : min(len(body), match.end() + 30)].strip()
                ev_id = context.record_evidence(
                    evidence_type="cleartext_web_storage_pattern",
                    data={
                        "snippet": snippet,
                        "url": url,
                    },
                    request_id=resp.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                    reason_description=f"Client JavaScript stores sensitive authentication tokens in browser Web Storage: '{snippet}'.",
                    evidence_ids=[ev_id],
                    request_ids=[resp.request_id],
                    confidence=90,
                )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTROL_ENFORCED,
            reason_description="No insecure token storage in client-side Web Storage was detected.",
            confidence=85,
        )


VerificationRegistry.register(CleartextStorageVerificationStrategy)
