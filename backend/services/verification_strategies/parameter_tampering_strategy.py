"""Parameter Tampering Verification Strategy."""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from backend.services.verification_engine import (
    VerificationStatus,
    VerificationReasonCode,
    VerificationConclusion,
    BaseVerificationStrategy,
    VerificationContext,
    VerificationContract,
)
from backend.services.request_engine import RequestSpec, RequestTimeout

class ParameterTamperingVerificationStrategy(BaseVerificationStrategy):
    contract = VerificationContract(
        check_id="C073_Parameter_Tampering",
        name="Parameter Tampering Verification (Dedicated)",
        security_property="Financial and business transaction values must be computed and validated strictly on the server",
        required_evidence_fields=["observed_data"],
        destructive=False,
    )

    async def verify(self, ctx: VerificationContext) -> VerificationConclusion:
        observed_data = ctx.candidate_evidence.get("observed_data", {})
        param_name = observed_data.get("parameter")
        
        if not param_name:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                reason_description="No parameter specified in observed_data",
                confidence=0
            )

        target_url = ctx.target_url
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        tampered_val = "-1.00"
        test_params = dict(params)
        test_params[param_name] = [tampered_val]
        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        spec = RequestSpec(
            url=test_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        
        resp = await ctx.send_verification_request(spec)
        ctx.record_evidence("TAMPER_RESPONSE", {"status": resp.response_status, "url": test_url}, resp.request_id)

        if not resp.success:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description="Tampered request failed",
                confidence=0
            )

        if resp.response_status == 200:
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description=f"Server accepted negative value {tampered_val} with HTTP 200.",
                confidence=90,
                evidence_ids=[ev.evidence_id for ev in ctx.collected_evidence],
                request_ids=[resp.request_id]
            )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTROL_ENFORCED,
            reason_description=f"Server rejected tampered value with HTTP {resp.response_status}.",
            confidence=90
        )
