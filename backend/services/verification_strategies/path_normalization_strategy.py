"""Verification strategy for C056: Path Normalization Inconsistency."""

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
from urllib.parse import urljoin, urlparse, urlunparse


class PathNormalizationVerificationStrategy(BaseVerificationStrategy):
    """Verifies path normalization discrepancies between reverse proxies and origin servers."""

    contract = VerificationContract(
        check_id="C056_Path_Normalization",
        name="Path Normalization Verification",
        security_property="Reverse proxies and application servers must normalize URL paths identically before evaluating routing or ACL rules.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    NORMALIZATION_PROBES = [
        ("/..;/", "Tomcat Matrix Parameter Semicolon (/..;/)"),
        ("/%2e%2e/", "URL-encoded Dot Dot (/%2e%2e/)"),
        ("/static/..%2fadmin", "Encoded Slash Traversal (..%2f)"),
    ]

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        url = context.candidate_evidence.get("affected_url") or context.target_url
        base = url.rstrip("/")

        for path_suffix, desc in self.NORMALIZATION_PROBES:
            probe_url = f"{base}{path_suffix}"
            spec = RequestSpec(
                url=probe_url,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            resp = await context.send_verification_request(spec)
            if not resp or not resp.success:
                continue

            # If the matrix or traversal probe produces a 200 OK with significant content
            if resp.response_status == 200 and len(resp.response_body or "") > 50:
                ev_id = context.record_evidence(
                    evidence_type="path_normalization_inconsistency",
                    data={
                        "probe_url": probe_url,
                        "variant": path_suffix,
                        "desc": desc,
                        "status_code": resp.response_status,
                    },
                    request_id=resp.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                    reason_description=f"Path normalization discrepancy verified: URL variant '{path_suffix}' ({desc}) returned HTTP 200 OK.",
                    evidence_ids=[ev_id],
                    request_ids=[resp.request_id],
                    confidence=85,
                )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTROL_ENFORCED,
            reason_description="Server/proxy correctly normalized or rejected matrix parameter and encoded traversal probes.",
            confidence=85,
        )


VerificationRegistry.register(PathNormalizationVerificationStrategy)
