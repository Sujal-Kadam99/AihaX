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
from urllib.parse import urlparse


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
        ("/admin/..;/", "/admin/", "Tomcat Matrix Parameter Semicolon (/..;/)"),
        ("/%2e%2e/", "/", "URL-encoded Dot Dot (/%2e%2e/)"),
        ("/static/..%2fadmin", "/static/admin", "Encoded Slash Traversal (..%2f)"),
    ]

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        url = context.candidate_evidence.get("affected_url") or context.target_url
        payload = context.candidate_evidence.get("payload")
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        selected = next((item for item in self.NORMALIZATION_PROBES if item[0] == payload), None)
        probes = [selected] if selected else self.NORMALIZATION_PROBES
        request_ids: list[str] = []
        evidence_ids: list[str] = []

        for variant_path, baseline_path, desc in probes:
            baseline = await context.send_verification_request(RequestSpec(
                url=origin + baseline_path,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            ))
            variant = await context.send_verification_request(RequestSpec(
                url=origin + variant_path,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            ))
            request_ids.extend([baseline.request_id, variant.request_id])
            if not baseline.success or not variant.success:
                continue

            baseline_body = baseline.response_body or ""
            variant_body = variant.response_body or ""
            generic_spa = "<!doctype html" in variant_body.lower() and (
                "juice shop" in variant_body.lower() or "<app-root" in variant_body.lower()
            )
            if (
                baseline.response_status in (401, 403)
                and variant.response_status == 200
                and not generic_spa
                and variant_body != baseline_body
            ):
                ev_id = context.record_evidence(
                    evidence_type="protected_path_normalization_bypass",
                    data={
                        "baseline_url": origin + baseline_path,
                        "baseline_status": baseline.response_status,
                        "variant_url": origin + variant_path,
                        "variant_status": variant.response_status,
                        "variant_differs_from_baseline": True,
                    },
                    request_id=variant.request_id,
                )
                evidence_ids.append(ev_id)
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                    reason_description=f"Canonical path returned HTTP {baseline.response_status}, while variant '{variant_path}' returned distinct HTTP 200 content.",
                    evidence_ids=evidence_ids,
                    request_ids=request_ids,
                    confidence=90,
                )

            ev_id = context.record_evidence(
                evidence_type="no_protected_access_bypass_observed",
                data={
                    "baseline_status": baseline.response_status,
                    "variant_status": variant.response_status,
                    "same_response_body": baseline_body == variant_body,
                    "generic_spa_response": generic_spa,
                },
                request_id=variant.request_id,
            )
            evidence_ids.append(ev_id)

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTROL_ENFORCED,
            reason_description="No path variant bypassed an authentication/authorization response with distinct protected content; an HTTP 200 alone did not establish impact.",
            evidence_ids=evidence_ids,
            request_ids=request_ids,
            confidence=90,
        )


VerificationRegistry.register(PathNormalizationVerificationStrategy)
