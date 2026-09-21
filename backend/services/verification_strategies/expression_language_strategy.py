"""Deterministic Expression Language (EL) Injection Verification Strategy (C035)."""

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


class ExpressionLanguageVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies Expression Language Injection (C035) by evaluating deterministic
    Java EL expressions (Spring SpEL, OGNL, JUEL) such as ${31330+7} -> 31337 or
    T(java.lang.Math).min(10,20) -> 10, confirming calculated arithmetic execution.
    """

    contract = VerificationContract(
        check_id="C035_EL_Injection",
        name="Expression Language Injection Verification",
        security_property="User parameters must never be evaluated dynamically within Java Expression Language parser contexts.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    EL_VERIFICATION_PROBES = [
        ("${31330+7}", "31337", "JSP EL / JUEL"),
        ("#{31330+7}", "31337", "JSF / Unified EL"),
        ("%{(31330+7)}", "31337", "Struts OGNL"),
        ("T(java.lang.Math).min(10,20)", "10", "Spring SpEL"),
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
            param_name = "expr"

        # Fetch baseline
        try:
            base_resp = await context.send_verification_request(RequestSpec(url=context.target_url, method="GET"))
            base_body = base_resp.response_body if base_resp.success else ""
        except Exception:
            base_body = ""

        last_resp = None
        for probe, expected_val, el_type in self.EL_VERIFICATION_PROBES:
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
            # Critical EL confirmation: calculated value is in body, but raw expression is NOT reflected
            if expected_val in body and probe not in body:
                ev_id = context.record_evidence(
                    evidence_type="el_evaluated_expression",
                    data={
                        "el_type": el_type,
                        "probe": probe,
                        "evaluated_result": expected_val,
                    },
                    request_id=resp.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                    reason_description=f"Expression Language Injection confirmed: Expression '{probe}' evaluated dynamically to '{expected_val}' ({el_type}).",
                    evidence_ids=[ev_id],
                    request_ids=[resp.request_id],
                    confidence=95,
                )

        ev_id = context.record_evidence(
            evidence_type="el_negative_control",
            data={"status": "not_evaluated"},
            request_id=last_resp.request_id if last_resp else None,
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.INPUT_SAFELY_ENCODED,
            reason_description="Expression Language expressions were not dynamically evaluated by the server.",
            evidence_ids=[ev_id],
            confidence=90,
        )


VerificationRegistry.register(ExpressionLanguageVerificationStrategy)
