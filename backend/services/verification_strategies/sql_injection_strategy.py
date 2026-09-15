from backend.services.verification_engine import (
    BaseVerificationStrategy,
    VerificationContract,
    VerificationConclusion,
    VerificationContext,
    VerificationStatus,
    VerificationReasonCode,
)
from backend.services.request_engine import RequestSpec
from backend.services.verification_strategies.request_builder import build_injected_request

class SqlInjectionVerificationStrategy(BaseVerificationStrategy):
    contract = VerificationContract(
        check_id="C023_SQL_Injection",
        name="SQL Injection Verification",
        security_property="Target reflects explicit database syntax errors or evaluates boolean logic affecting response content.",
        required_evidence_fields=["affected_url", "affected_param", "payload", "proof_request"],
        destructive=False,
    )

    DB_ERRORS = [
        "SQL syntax",
        "mysql_fetch",
        "ORA-01756",
        "PostgreSQL query failed",
        "SQLite/JDBCDriver",
        "Unclosed quotation mark after the character string",
    ]

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        
        # 1. Baseline Request
        spec_baseline = build_injected_request(candidate, candidate.get("payload", ""))
        if not spec_baseline:
            ev_id = context.record_evidence(
                evidence_type="missing_evidence",
                data={"reason": "Could not parse injection point or missing proof_request."}
            )
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.MISSING_EVIDENCE,
                reason_description="Candidate finding lacks precise injection point or parsing failed.",
                evidence_ids=[ev_id],
                confidence=0
            )

        successful_request_ids = []

        async def send_safe(spec: RequestSpec):
            try:
                resp = await context.send_verification_request(spec)
                if resp and resp.success and resp.request_id:
                    successful_request_ids.append(resp.request_id)
                return resp
            except Exception as e:
                # E.g., BudgetExceededError or Network error inside engine
                return None

        # Fetch Baseline
        resp_baseline = await send_safe(spec_baseline)
        if not resp_baseline or not resp_baseline.success:
            ev_id = context.record_evidence("baseline_failed", {"reason": "Baseline request failed or timeout."})
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description="Failed to fetch baseline response.",
                evidence_ids=[ev_id],
                request_ids=successful_request_ids,
                confidence=0
            )

        baseline_body_lower = (resp_baseline.response_body or "").lower()

        # 2. Error-Based Testing
        spec_error = build_injected_request(candidate, "'")
        resp_error = await send_safe(spec_error)

        if resp_error and resp_error.success and resp_error.response_body:
            body_lower = resp_error.response_body.lower()
            for err in self.DB_ERRORS:
                # Ensure the error is unique to the injected response
                if err.lower() in body_lower and err.lower() not in baseline_body_lower:
                    ev_id = context.record_evidence(
                        evidence_type="sql_error_detected",
                        data={"matched_error": err, "payload_used": "'"},
                        request_id=resp_error.request_id,
                    )
                    return VerificationConclusion(
                        status=VerificationStatus.VERIFIED,
                        reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
                        reason_description=f"Explicit database syntax error '{err}' reflected uniquely in response.",
                        evidence_ids=[ev_id],
                        request_ids=successful_request_ids,
                        confidence=100,
                    )

        # 3. Variance Measurement (Fetch Baseline Again)
        resp_baseline2 = await send_safe(spec_baseline)
        variance_len = 0
        if resp_baseline2 and resp_baseline2.success:
            body2 = resp_baseline2.response_body or ""
            variance_len = abs(len(resp_baseline.response_body or "") - len(body2))

        # 4. Boolean-Based Testing
        spec_true = build_injected_request(candidate, "' OR '1'='1")
        spec_false = build_injected_request(candidate, "' OR '1'='0")

        resp_true = await send_safe(spec_true)
        resp_false = await send_safe(spec_false)

        if resp_true and resp_true.success and resp_false and resp_false.success:
            body_true = resp_true.response_body or ""
            body_false = resp_false.response_body or ""
            body_base = resp_baseline.response_body or ""

            len_true = len(body_true)
            len_false = len(body_false)
            len_base = len(body_base)

            diff_true_base = abs(len_true - len_base)
            diff_false_true = abs(len_false - len_true)
            diff_false_base = abs(len_false - len_base)

            # Meaningful divergence requires exceeding natural variance and a static minimum
            threshold = max(variance_len * 2, 50, int(len_base * 0.05))

            is_false_collapse = (
                diff_false_true > threshold and 
                diff_false_base > threshold and 
                len_false < len_base and 
                len_false < len_true
            )
            
            is_true_expand = (
                diff_false_true > threshold and
                diff_true_base > threshold and
                len_true > len_base and
                len_true > len_false
            )
            
            is_flat_true = (
                diff_false_true > threshold and 
                diff_false_base > threshold and 
                diff_true_base <= threshold
            )

            if is_false_collapse or is_true_expand or is_flat_true:
                pattern = "collapse" if is_false_collapse else ("expand" if is_true_expand else "flat")
                ev_id = context.record_evidence(
                    evidence_type="boolean_diff_detected",
                    data={
                        "true_len": len_true,
                        "false_len": len_false,
                        "base_len": len_base,
                        "threshold": threshold,
                        "variance": variance_len,
                        "pattern": pattern
                    },
                    request_id=resp_false.request_id,
                )
                return VerificationConclusion(
                    status=VerificationStatus.VERIFIED,
                    reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
                    reason_description=f"Boolean-based differential response confirmed (pattern: {pattern}).",
                    evidence_ids=[ev_id],
                    request_ids=successful_request_ids,
                    confidence=95,
                )

        # 5. Fallback: Inconclusive
        ev_id = context.record_evidence(
            evidence_type="differential_failed",
            data={"reason": "No unique DB errors and no meaningful boolean difference"}
        )
        return VerificationConclusion(
            status=VerificationStatus.INCONCLUSIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description="No database errors reflected and no meaningful boolean differences observed.",
            evidence_ids=[ev_id],
            request_ids=successful_request_ids,
            confidence=0,
        )
