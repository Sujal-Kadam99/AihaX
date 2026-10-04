"""Verification strategy for C051: Cross-Domain Policy Misconfiguration."""

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
from urllib.parse import urljoin


class CrossDomainPolicyVerificationStrategy(BaseVerificationStrategy):
    """Verifies whether crossdomain.xml or clientaccesspolicy.xml permits wildcard access to untrusted domains."""

    contract = VerificationContract(
        check_id="C051_Cross_Domain_Policy",
        name="Cross-Domain Policy Verification",
        security_property="Cross-domain policy files must not grant wildcard access (*) to untrusted domains.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    POLICY_FILES = ["/crossdomain.xml", "/clientaccesspolicy.xml"]

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        url = context.candidate_evidence.get("affected_url") or context.target_url
        base = url.rstrip("/")
        
        # If the candidate URL is already pointing to the XML policy file
        candidate_files = [url] if any(url.endswith(p) for p in self.POLICY_FILES) else [urljoin(base + "/", p.lstrip("/")) for p in self.POLICY_FILES]

        for policy_url in candidate_files:
            spec = RequestSpec(
                url=policy_url,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            resp = await context.send_verification_request(spec)
            if not resp or not resp.success or resp.response_status != 200:
                continue

            body = resp.response_body or ""
            # Check for overly permissive wildcard domain rules
            if ('domain="*"' in body or "domain='*'" in body or 'uri="*"' in body or "<allow-from http-request-headers" in body) and "<" in body:
                ev_id = context.record_evidence(
                    evidence_type="wildcard_cross_domain_policy",
                    data={
                        "policy_url": policy_url,
                        "status_code": resp.response_status,
                        "content_preview": body[:300],
                    },
                    request_id=resp.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                    reason_description=f"Overly permissive cross-domain policy granting wildcard domain access (*) verified at '{policy_url}'.",
                    evidence_ids=[ev_id],
                    request_ids=[resp.request_id],
                    confidence=95,
                )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTROL_ENFORCED,
            reason_description="No overly permissive wildcard cross-domain policy files were accessible.",
            confidence=90,
        )


VerificationRegistry.register(CrossDomainPolicyVerificationStrategy)
