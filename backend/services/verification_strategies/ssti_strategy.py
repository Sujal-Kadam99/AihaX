"""Deterministic Server-Side Template Injection (SSTI) Verification Strategy (C028)."""

from __future__ import annotations

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


class SstiVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies Server-Side Template Injection (C028) by evaluating deterministic
    arithmetic expressions (e.g. {{31330+7}} -> 31337) and verifying that the computed
    value appears in the response body while the unparsed literal expression is NOT reflected.
    """

    contract = VerificationContract(
        check_id="C028_SSTI",
        name="Server-Side Template Injection Verification",
        security_property="Template engines must strictly evaluate user input as data rather than dynamic executable template code.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    SSTI_VERIFICATION_PROBES = [
        ("{{31330+7}}", "31337", "Jinja2/Twig"),
        ("${31330+7}", "31337", "Freemarker/MVEL"),
        ("#{31330+7}", "31337", "Thymeleaf/Spring"),
        ("<%= 31330+7 %>", "31337", "ERB/Ruby"),
        ("{{7*7}}", "49", "Jinja2/Twig"),
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
            param_name = "name"

        # Fetch baseline to eliminate false positives from static numbers on the page
        try:
            base_resp = await context.send_verification_request(RequestSpec(url=context.target_url, method="GET"))
            base_body = base_resp.response_body if base_resp.success else ""
        except Exception:
            base_body = ""

        last_resp = None
        for probe, expected_val, engine_type in self.SSTI_VERIFICATION_PROBES:
            if expected_val in base_body:
                continue

            test_params = dict(params)
            test_params[param_name] = [probe]
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
            # Critical SSTI confirmation: computed result is in body, but raw expression is NOT reflected
            if expected_val in body and probe not in body:
                ev_id = context.record_evidence(
                    evidence_type="ssti_evaluated_expression",
                    data={
                        "engine_type": engine_type,
                        "probe": probe,
                        "evaluated_result": expected_val,
                    },
                    request_id=resp.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                    reason_description=f"Server-Side Template Injection confirmed: Template expression '{probe}' evaluated dynamically to '{expected_val}' ({engine_type}).",
                    evidence_ids=[ev_id],
                    request_ids=[resp.request_id],
                    confidence=95,
                )

        ev_id = context.record_evidence(
            evidence_type="ssti_negative_control",
            data={"status": "not_evaluated"},
            request_id=last_resp.request_id if last_resp else None,
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.INPUT_SAFELY_ENCODED,
            reason_description="Template expressions were not dynamically evaluated into computed arithmetic results.",
            evidence_ids=[ev_id],
            confidence=90,
        )


VerificationRegistry.register(SstiVerificationStrategy)
