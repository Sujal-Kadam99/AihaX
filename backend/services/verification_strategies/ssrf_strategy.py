"""Deterministic, Safe SSRF Verification Strategy for AihaX (C036)."""

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


class SsrfVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies Server-Side Request Forgery (C036) by sending a bounded probe targeting
    an in-scope resource (e.g. /robots.txt), confirming that the server initiates outbound
    fetching or returns proxied resource content rather than rejecting or sanitizing the URL parameter.
    """

    contract = VerificationContract(
        check_id="C036_SSRF_Indicators",
        name="Server-Side Request Forgery Verification",
        security_property="Server-side URL fetching must restrict destinations to an explicit allowlist and prevent arbitrary outbound network requests.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url
        param_name = candidate.get("affected_param")

        if context.budget.max_requests < 2:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description="Insufficient request budget for SSRF verification.",
            )

        parsed = urlparse(affected_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not param_name and params:
            param_name = list(params.keys())[0]
        if not param_name:
            param_name = "url"

        # 1. Probe using safe in-scope canary path
        safe_canary_target = f"{parsed.scheme or 'http'}://{parsed.netloc or '127.0.0.1'}/robots.txt"
        test_params = dict(params)
        test_params[param_name] = [safe_canary_target]
        new_query = urlencode(test_params, doseq=True)
        probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        probe_spec = RequestSpec(
            url=probe_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        try:
            resp = await context.send_verification_request(probe_spec)
        except Exception as exc:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description=f"SSRF verification probe failed: {exc}",
            )

        body = resp.response_body or ""
        # Evidence: Proxied content (robots.txt markers or canary marker) in response body
        if "User-agent:" in body or "Disallow:" in body or "aihax-ssrf-canary" in body.lower():
            ev_id = context.record_evidence(
                evidence_type="ssrf_proxied_content",
                data={
                    "target": safe_canary_target,
                    "param": param_name,
                    "snippet": body[:200],
                },
                request_id=resp.request_id,
            )
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description=f"Server-Side Request Forgery confirmed: Server fetched and proxied the requested in-scope resource '{safe_canary_target}' into response body.",
                evidence_ids=[ev_id],
                request_ids=[resp.request_id],
                confidence=95,
            )

        # 2. Control check: probe with an unresolvable dummy canary URL
        control_target = "https://aihax-ssrf-negative-control-invalid.test/canary"
        ctrl_params = dict(params)
        ctrl_params[param_name] = [control_target]
        ctrl_query = urlencode(ctrl_params, doseq=True)
        ctrl_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, ctrl_query, parsed.fragment))

        ctrl_spec = RequestSpec(
            url=ctrl_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        try:
            ctrl_resp = await context.send_verification_request(ctrl_spec)
            ctrl_body = ctrl_resp.response_body or ""
            if any(err in ctrl_body.lower() for err in ["getaddrinfo", "nameresolutionerror", "connection refused", "curl error", "could not resolve host"]):
                ev_id = context.record_evidence(
                    evidence_type="ssrf_outbound_dns_error",
                    data={
                        "target": control_target,
                        "param": param_name,
                        "snippet": ctrl_body[:200],
                    },
                    request_id=ctrl_resp.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                    reason_description=f"Server-Side Request Forgery confirmed: Server attempted outbound network resolution for untrusted host '{control_target}' disclosing network fetch errors.",
                    evidence_ids=[ev_id],
                    request_ids=[ctrl_resp.request_id],
                    confidence=90,
                )
        except Exception:
            pass

        ev_id = context.record_evidence(
            evidence_type="ssrf_rejected",
            data={"status_code": resp.response_status},
            request_id=resp.request_id,
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTROL_ENFORCED,
            reason_description="Server did not fetch or proxy the supplied URL parameter; SSRF not reproducible.",
            evidence_ids=[ev_id],
            request_ids=[resp.request_id],
            confidence=85,
        )


VerificationRegistry.register(SsrfVerificationStrategy)
