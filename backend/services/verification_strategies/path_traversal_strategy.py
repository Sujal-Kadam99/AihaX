"""Deterministic Path Traversal Verification Strategy (C031)."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

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


class PathTraversalVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies Path Traversal (C031) by sending bounded traversal payloads targeting standard
    operating system files (/etc/passwd, win.ini) and confirming genuine file markers (e.g. root:.*:0:0: or [fonts])
    in the response body.
    """

    contract = VerificationContract(
        check_id="C031_Path_Traversal",
        name="Path Traversal Verification",
        security_property="File path parameters must be sanitized and strictly constrained to authorized directories without arbitrary path traversal.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    TRAVERSAL_VERIFICATION_PROBES = [
        ("../../../../etc/passwd", re.compile(r"root:.*:0:0:", re.I), "Linux /etc/passwd"),
        ("/etc/passwd", re.compile(r"root:.*:0:0:", re.I), "Absolute /etc/passwd"),
        ("..\\..\\..\\..\\windows\\win.ini", re.compile(r"\[(?:fonts|extensions|files)\]", re.I), "Windows win.ini"),
        ("..%2f..%2f..%2f..%2fetc%2fpasswd", re.compile(r"root:.*:0:0:", re.I), "URL-Encoded /etc/passwd"),
    ]

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url
        param_name = candidate.get("affected_param")

        parsed = urlparse(affected_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not param_name and params:
            param_name = list(params.keys())[0]
        if not param_name:
            param_name = "file"

        last_resp = None
        for payload, marker_pat, os_hint in self.TRAVERSAL_VERIFICATION_PROBES:
            test_params = dict(params)
            test_params[param_name] = [payload]
            new_query = urlencode(test_params, doseq=True)
            probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            probe_spec = RequestSpec(
                url=probe_url,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            try:
                resp = await context.send_verification_request(probe_spec)
                last_resp = resp
            except Exception:
                continue

            if not resp.success:
                continue

            body = resp.response_body or ""
            match = marker_pat.search(body)
            if match:
                snippet = body[max(0, match.start() - 10) : min(len(body), match.end() + 50)].replace("\n", " ")
                ev_id = context.record_evidence(
                    evidence_type="path_traversal_disclosure",
                    data={
                        "target_file": os_hint,
                        "payload": payload,
                        "file_snippet": snippet,
                    },
                    request_id=resp.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                    reason_description=f"Path Traversal confirmed: Traversal payload '{payload}' successfully read {os_hint} disclosing file contents: '{snippet}'.",
                    evidence_ids=[ev_id],
                    request_ids=[resp.request_id],
                    confidence=95,
                )

        ev_id = context.record_evidence(
            evidence_type="path_traversal_negative_control",
            data={"status": "access_denied_or_file_absent"},
            request_id=last_resp.request_id if last_resp else None,
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTROL_ENFORCED,
            reason_description="Path traversal sequences failed to return arbitrary file contents from the target filesystem.",
            evidence_ids=[ev_id],
            confidence=90,
        )


VerificationRegistry.register(PathTraversalVerificationStrategy)
