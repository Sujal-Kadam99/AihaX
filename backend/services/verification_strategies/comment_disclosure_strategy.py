"""Verification strategy for C060: Information Disclosure in Source Comments."""

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


class CommentInformationDisclosureVerificationStrategy(BaseVerificationStrategy):
    """Verifies whether source comments in HTML/JS leak sensitive architecture details, secrets, or credentials."""

    contract = VerificationContract(
        check_id="C060_Comment_Information_Disclosure",
        name="Source Comment Disclosure Verification",
        security_property="Production HTML and JavaScript assets must strip developer comments and internal notes.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    COMMENT_PATTERNS = [
        ("Database Credentials Note", re.compile(r"(?:<!--|/\*|//)[^>]*?(?:password\s*=|pwd\s*=|db_pass\s*=)[^>]*?(?:-->|\*/|\n)", re.I)),
        ("Internal Architecture Note", re.compile(r"(?:<!--|/\*|//)[^>]*?(?:TODO:\s*remove|FIXME:\s*security|internal\s*ip:\s*10\.|internal\s*ip:\s*192\.168\.)[^>]*?(?:-->|\*/|\n)", re.I)),
        ("Admin Credential Comment", re.compile(r"(?:<!--|/\*|//)[^>]*?(?:admin:\s*\w+|login:\s*admin)[^>]*?(?:-->|\*/|\n)", re.I)),
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
                reason_description="Target unreachable during source comment verification probe.",
            )

        body = resp.response_body or ""
        for desc, pat in self.COMMENT_PATTERNS:
            match = pat.search(body)
            if match:
                snippet = match.group(0).strip()[:200].replace("\n", " ")
                ev_id = context.record_evidence(
                    evidence_type="sensitive_comment_discovered",
                    data={
                        "category": desc,
                        "snippet": snippet,
                        "url": url,
                    },
                    request_id=resp.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                    reason_description=f"Sensitive developer comment discovered in source: '{snippet}' ({desc}).",
                    evidence_ids=[ev_id],
                    request_ids=[resp.request_id],
                    confidence=90,
                )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTROL_ENFORCED,
            reason_description="No sensitive developer comments or credential disclosures were found in source code.",
            confidence=85,
        )


VerificationRegistry.register(CommentInformationDisclosureVerificationStrategy)
