"""Deterministic NoSQL Injection Verification Strategy (C025)."""

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


class NosqlInjectionVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies NoSQL Injection (C025) by sending boolean-differential and operator-based probes
    (e.g. param[$ne]=invalid vs param[$eq]=invalid) and verifying whether the operator alters query logic,
    returns differential data states, or discloses NoSQL database exceptions (MongoDB/BSON).
    """

    contract = VerificationContract(
        check_id="C025_NoSQL_Injection",
        name="NoSQL Injection Verification",
        security_property="Document database queries must validate parameter types and reject unsanitized query operator structures.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url
        param_name = candidate.get("affected_param")

        parsed = urlparse(affected_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not param_name and params:
            param_name = list(params.keys())[0]
        if not param_name:
            param_name = "user"

        # 1. Probe with MongoDB operator: param[$ne]=invalid_value_xyz
        test_params_ne = dict(params)
        if param_name in test_params_ne:
            del test_params_ne[param_name]
        test_params_ne[f"{param_name}[$ne]"] = ["aihax_unmatched_val_99x"]
        new_query_ne = urlencode(test_params_ne, doseq=True)
        ne_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query_ne, parsed.fragment))

        try:
            resp_ne = await context.send_verification_request(RequestSpec(url=ne_url, method="GET"))
        except Exception as exc:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description=f"NoSQL probe failed: {exc}",
            )

        if not resp_ne.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description="Network communication failed during NoSQL verification.",
            )

        body_ne = resp_ne.response_body or ""
        # Check for direct NoSQL/MongoDB error disclosure
        if any(err in body_ne for err in ["MongoError", "CastError", "BSONTypeError", "Cannot use 'in' operator to search for '$ne'"]):
            ev_id = context.record_evidence(
                evidence_type="nosql_database_error",
                data={"error_snippet": body_ne[:200]},
                request_id=resp_ne.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description=f"NoSQL Injection confirmed: MongoDB/BSON query engine error disclosed when injecting operator '{param_name}[$ne]'.",
                evidence_ids=[ev_id],
                request_ids=[resp_ne.request_id],
                confidence=95,
            )

        # 2. Differential probe: compare with false condition param[$eq]=invalid_value_xyz
        test_params_eq = dict(params)
        if param_name in test_params_eq:
            del test_params_eq[param_name]
        test_params_eq[f"{param_name}[$eq]"] = ["aihax_unmatched_val_99x"]
        new_query_eq = urlencode(test_params_eq, doseq=True)
        eq_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query_eq, parsed.fragment))

        try:
            resp_eq = await context.send_verification_request(RequestSpec(url=eq_url, method="GET"))
        except Exception:
            resp_eq = None

        if resp_eq and resp_eq.success:
            body_eq = resp_eq.response_body or ""
            # If $ne (not equal to unmatched) returns 200 with data while $eq (equal to unmatched) returns empty/404 or significantly fewer bytes
            if resp_ne.response_status == 200 and resp_eq.response_status in (200, 404):
                if len(body_ne) > len(body_eq) + 50 and resp_ne.response_status != resp_eq.response_status or (len(body_ne) > len(body_eq) * 1.5 and len(body_ne) > 100):
                    ev_id = context.record_evidence(
                        evidence_type="nosql_differential_response",
                        data={
                            "ne_length": len(body_ne),
                            "eq_length": len(body_eq),
                            "ne_status": resp_ne.response_status,
                            "eq_status": resp_eq.response_status,
                        },
                        request_id=resp_ne.request_id,
                    )
                    return VerificationConclusion(
                        status=VerificationStatus.VERIFIED,
                        reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                        reason_description=f"NoSQL Injection confirmed: Differential query outcome observed between operator '{param_name}[$ne]' (records returned) and '{param_name}[$eq]' (empty/filtered).",
                        evidence_ids=[ev_id],
                        request_ids=[resp_ne.request_id, resp_eq.request_id],
                        confidence=90,
                    )

        ev_id = context.record_evidence(
            evidence_type="nosql_negative_control",
            data={"status": "no_operator_effect"},
            request_id=resp_ne.request_id,
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTROL_ENFORCED,
            reason_description="NoSQL operator injection yielded no differential response behavior or database exceptions.",
            evidence_ids=[ev_id],
            confidence=85,
        )


VerificationRegistry.register(NosqlInjectionVerificationStrategy)
