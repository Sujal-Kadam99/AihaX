"""C063 — Cloud Storage Bucket Exposure Check for AihaX."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C063CloudBucketExposure(BaseCheck):
    contract = CheckContract(
        id="C063_Cloud_Bucket_Exposure",
        name="Cloud Storage Bucket Exposure",
        category=CheckCategory.SENSITIVE_DATA,
        description="Detects references to public cloud storage buckets (AWS S3, Google Cloud Storage, Azure Blob) that allow unauthenticated listing or anonymous read permissions (<ListBucketResult>).",
        severity=Severity.HIGH,
        vulnerability_type="Information Disclosure",
        cwe="CWE-200",
        owasp_category="A01:2021-Broken Access Control",
        security_property="Cloud storage buckets must block public read and bucket listing permissions",
        remediation_guidance="Enable S3 Block Public Access, restrict bucket policies, and remove anonymous list/read grants.",
        references=[
            "https://cwe.mitre.org/data/definitions/200.html",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "bucket_url"],
        destructive=False,
    )

    BUCKET_PATTERNS = [
        re.compile(r"https?://([a-zA-Z0-9.\-_]+)\.s3\.amazonaws\.com"),
        re.compile(r"https?://s3\.amazonaws\.com/([a-zA-Z0-9.\-_]+)"),
        re.compile(r"https?://storage\.googleapis\.com/([a-zA-Z0-9.\-_]+)"),
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        spec = RequestSpec(
            url=target_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp = await request_engine.execute(spec)
        if not resp.success:
            return None

        body = resp.response_body or ""
        discovered_buckets = set()
        for pat in self.BUCKET_PATTERNS:
            for match in pat.finditer(body):
                discovered_buckets.add(match.group(0))

        # Check if any discovered bucket allows public listing
        for bucket_url in list(discovered_buckets)[:3]:
            bucket_spec = RequestSpec(
                url=bucket_url,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            bucket_resp = await request_engine.execute(bucket_spec)
            if bucket_resp.success and bucket_resp.response_status == 200:
                b_body = bucket_resp.response_body or ""
                if "<ListBucketResult" in b_body or "<Contents>" in b_body:
                    return CheckResult(
                        check_id=self.contract.id,
                        title=self.contract.name,
                        target=target_url,
                        affected_url=bucket_url,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.HIGH,
                        candidate_reason=f"Publicly listable cloud storage bucket discovered at '{bucket_url}'.",
                        request_ids=[resp.request_id, bucket_resp.request_id],
                        evidence_ids=[resp.evidence_id, bucket_resp.evidence_id],
                        observed_data={"bucket_url": bucket_url, "status": bucket_resp.response_status},
                        payload=None,
                        proof_response=f"ListBucketResult XML Disclosed: {b_body[:150]}",
                        confidence=95,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C063CloudBucketExposure)
