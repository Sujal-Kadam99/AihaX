"""Directory Listing Verification Strategy.

Replays a GET to the affected directory path and checks whether the response
contains an Apache/Nginx/IIS-style directory listing (e.g. 'Index of /').
"""

import re
from backend.services.verification_engine import (
    VerificationStatus,
    VerificationReasonCode,
    VerificationConclusion,
    BaseVerificationStrategy,
    VerificationContext,
    VerificationContract,
)
from backend.services.request_engine import RequestSpec, RequestTimeout


class DirectoryListingVerificationStrategy(BaseVerificationStrategy):
    """
    Dedicated verification strategy for C006 Directory Listing findings.

    Replays the exact affected_url from the candidate finding and checks for
    directory listing indicators in the response body, plus scans for
    sensitive filenames that elevate severity.
    """

    contract = VerificationContract(
        check_id="C006_Directory_Listing",
        name="Directory Listing Verification (Dedicated)",
        security_property="Web server must not generate directory listings for directories without index documents.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    DIR_INDICATORS = [
        "Index of /",
        "Directory listing for",
        "<title>Index of",
        "[To Parent Directory]",
        "Last modified</a>",
    ]

    SENSITIVE_PATTERNS = [
        r"\.env\b", r"\.git\b", r"\.aws\b", r"\.ssh\b", r"\.sql\b",
        r"\.bak\b", r"\.backup\b", r"\.old\b", r"\.tar\b", r"\.gz\b",
        r"\.zip\b", r"\.dump\b", r"config\.(php|json|ya?ml|py|inc)\b",
        r"database\.(php|json|ya?ml|py|sqlite|db)\b", r"credentials?\b",
        r"password\b", r"secret\b", r"id_rsa\b", r"private_key\b",
        r"\.htpasswd\b",
    ]

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        if context.budget.max_requests <= 0:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description="Verification budget exhausted.",
            )

        affected_url = candidate.get("affected_url") or context.target_url

        spec = RequestSpec(
            url=affected_url,
            method="GET",
            follow_redirects=False,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        context.budget.max_requests -= 1
        response = await context.request_engine.execute(spec)

        if not response.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description="Endpoint failed to respond during directory listing verification.",
                request_ids=[response.request_id],
            )

        body = response.response_body or ""
        status = response.response_status

        matched_indicator = next(
            (ind for ind in self.DIR_INDICATORS if ind.lower() in body.lower()),
            None,
        )

        if status == 200 and matched_indicator:
            # Check for sensitive files in the listing
            sensitive_match = next(
                (pat for pat in self.SENSITIVE_PATTERNS if re.search(pat, body, re.IGNORECASE)),
                None,
            )

            ev_id = context.record_evidence(
                evidence_type="directory_listing_verified",
                data={
                    "status": status,
                    "matched_indicator": matched_indicator,
                    "sensitive_pattern": sensitive_match,
                    "body_snippet": body[:300],
                },
                request_id=response.request_id,
            )

            if sensitive_match:
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
                    reason_description=(
                        f"Directory listing on '{affected_url}' confirmed with indicator "
                        f"'{matched_indicator}' and sensitive file pattern '{sensitive_match}'."
                    ),
                    evidence_ids=[ev_id],
                    request_ids=[response.request_id],
                    confidence=95,
                )

            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
                reason_description=(
                    f"Directory listing confirmed on '{affected_url}' with indicator "
                    f"'{matched_indicator}'. No sensitive files detected in listing."
                ),
                evidence_ids=[ev_id],
                request_ids=[response.request_id],
                confidence=80,
            )

        # No directory listing indicators found
        ev_id = context.record_evidence(
            evidence_type="directory_listing_not_found",
            data={"status": status, "body_snippet": body[:200]},
            request_id=response.request_id,
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description=f"Directory listing not observed on '{affected_url}' (HTTP {status}).",
            evidence_ids=[ev_id],
            request_ids=[response.request_id],
            confidence=100,
        )
