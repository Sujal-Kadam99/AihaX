"""Verification strategy for C063: Cloud Storage Bucket Exposure."""

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


class CloudBucketExposureVerificationStrategy(BaseVerificationStrategy):
    """Verifies whether referenced cloud storage buckets allow anonymous/public listing."""

    contract = VerificationContract(
        check_id="C063_Cloud_Bucket_Exposure",
        name="Cloud Bucket Exposure Verification",
        security_property="Cloud storage buckets must deny anonymous/public bucket listing permissions.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    BUCKET_PATTERNS = [
        re.compile(r"https?://([a-zA-Z0-9.\-_]+)\.s3\.amazonaws\.com"),
        re.compile(r"https?://s3\.amazonaws\.com/([a-zA-Z0-9.\-_]+)"),
        re.compile(r"https?://storage\.googleapis\.com/([a-zA-Z0-9.\-_]+)"),
    ]

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        url = context.candidate_evidence.get("affected_url") or context.target_url
        candidate_bucket = context.candidate_evidence.get("bucket_url") or url

        # If candidate is already a bucket URL or contains bucket URL
        tested_buckets = set()
        if any(b in candidate_bucket for b in ["s3.amazonaws.com", "storage.googleapis.com"]):
            tested_buckets.add(candidate_bucket)

        # Also extract any bucket URLs from target page
        spec = RequestSpec(
            url=context.target_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp = await context.send_verification_request(spec)
        if resp and resp.success:
            body = resp.response_body or ""
            for pat in self.BUCKET_PATTERNS:
                for match in pat.finditer(body):
                    tested_buckets.add(match.group(0))

        for bucket_url in list(tested_buckets)[:3]:
            bucket_spec = RequestSpec(
                url=bucket_url,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            bucket_resp = await context.send_verification_request(bucket_spec)
            if not bucket_resp or not bucket_resp.success:
                continue

            b_body = bucket_resp.response_body or ""
            # Verify public listing XML
            if bucket_resp.response_status == 200 and ("<ListBucketResult" in b_body or "<Contents>" in b_body):
                ev_id = context.record_evidence(
                    evidence_type="cloud_bucket_public_listing",
                    data={
                        "bucket_url": bucket_url,
                        "status_code": bucket_resp.response_status,
                        "xml_preview": b_body[:300],
                    },
                    request_id=bucket_resp.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                    reason_description=f"Publicly listable cloud storage bucket confirmed: '{bucket_url}' exposes object listing XML.",
                    evidence_ids=[ev_id],
                    request_ids=[bucket_resp.request_id],
                    confidence=95,
                )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTROL_ENFORCED,
            reason_description="No publicly listable cloud storage buckets were accessible.",
            confidence=90,
        )


VerificationRegistry.register(CloudBucketExposureVerificationStrategy)
