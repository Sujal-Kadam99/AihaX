import time
from typing import Optional
from backend.services.verification_engine import (
    BaseVerificationStrategy,
    VerificationContract,
    VerificationConclusion,
    VerificationContext,
    VerificationStatus,
    VerificationReasonCode,
)
from datetime import datetime, timezone
from backend.services.request_engine import RequestSpec, RequestEvidence
from backend.services.verification_strategies.request_builder import build_injected_request

class BlindSqlInjectionVerificationStrategy(BaseVerificationStrategy):
    contract = VerificationContract(
        check_id="C024_Blind_SQL_Injection",
        name="Blind SQL Injection Verification",
        security_property="Target processes database queries synchronously and allows arbitrary time delays via SQL logic.",
        required_evidence_fields=["affected_url", "affected_param", "payload", "proof_request"],
        destructive=False,
    )

    # 5-second sleeps for various DBs, with corresponding 0-second controls
    PAYLOADS = [
        {"db": "MySQL", "sleep": "' AND SLEEP(5)-- -", "control": "' AND SLEEP(0)-- -"},
        {"db": "PostgreSQL", "sleep": "' AND pg_sleep(5)-- -", "control": "' AND pg_sleep(0)-- -"},
        {"db": "MSSQL", "sleep": "'; WAITFOR DELAY '0:0:5'-- -", "control": "'; WAITFOR DELAY '0:0:0'-- -"},
        # Integer contexts
        {"db": "MySQL (Int)", "sleep": " AND SLEEP(5)-- -", "control": " AND SLEEP(0)-- -"},
        {"db": "PostgreSQL (Int)", "sleep": " AND pg_sleep(5)-- -", "control": " AND pg_sleep(0)-- -"},
    ]

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        
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

        async def send_safe(spec: RequestSpec, is_sleep_test: bool = False) -> Optional[RequestEvidence]:
            try:
                resp = await context.send_verification_request(spec)
                if resp and resp.request_id:
                    successful_request_ids.append(resp.request_id)
                return resp
            except Exception as e:
                err_str = str(e).lower()
                is_timeout = "timeout" in err_str or "readtimeout" in err_str or "connecttimeout" in err_str or "timed out" in err_str
                
                # If a timeout occurs on a sleep payload, it's strong evidence of the payload working
                if is_timeout and is_sleep_test:
                    req_id = f"timeout-{int(time.time())}"
                    timeout_val = getattr(spec.timeout, "total", 15.0) if hasattr(spec, "timeout") else 15.0
                    ev = RequestEvidence(
                        request_id=req_id,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        method=spec.method,
                        url=spec.url,
                        request_headers=spec.headers,
                        request_body=str(spec.body) if spec.body else None,
                        response_status=408,
                        response_headers={},
                        response_body="",
                        response_size=0,
                        duration_ms=timeout_val * 1000.0,
                        truncated=False,
                        redirect_chain=[],
                        scope_decision={"allowed": True},
                        transport_error={"error_type": "timeout", "message": "Simulated timeout evidence"},
                        request_hash="",
                        response_hash="",
                        success=False
                    )
                    successful_request_ids.append(req_id)
                    return ev
                return None

        # 1. Baseline latency check
        resp_baseline = await send_safe(spec_baseline)
        if not resp_baseline:
            ev_id = context.record_evidence("baseline_failed", {"reason": "Baseline request failed or timeout."})
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description="Failed to fetch baseline response.",
                evidence_ids=[ev_id],
                request_ids=successful_request_ids,
                confidence=0
            )

        baseline_duration = resp_baseline.duration_ms
        if baseline_duration > 2000.0:
            ev_id = context.record_evidence("noisy_baseline", {"duration_ms": baseline_duration})
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
                reason_description=f"Baseline response is too slow ({baseline_duration}ms). Timing side-channel is unreliable.",
                evidence_ids=[ev_id],
                request_ids=successful_request_ids,
                confidence=0
            )

        # We are testing for a 5-second sleep. We want duration > baseline + 4000ms.
        sleep_threshold = baseline_duration + 4000.0
        # Control should be near baseline. We tolerate up to baseline + 2000ms max.
        control_threshold = baseline_duration + 2000.0

        tech_stack = candidate.get("tech_stack", [])
        if isinstance(tech_stack, str):
            tech_stack = [tech_stack]
        tech_stack = [t.lower() for t in tech_stack]
        
        ordered_payloads = list(self.PAYLOADS)
        if "mysql" in tech_stack:
            ordered_payloads.sort(key=lambda p: 0 if "MySQL" in p["db"] else 1)
        elif "postgresql" in tech_stack or "postgres" in tech_stack:
            ordered_payloads.sort(key=lambda p: 0 if "PostgreSQL" in p["db"] else 1)
        elif "mssql" in tech_stack or "sqlserver" in tech_stack:
            ordered_payloads.sort(key=lambda p: 0 if "MSSQL" in p["db"] else 1)

        for payload_set in ordered_payloads:
            if context.requests_made >= context.budget.max_requests:
                ev_id = context.record_evidence(
                    evidence_type="budget_exhausted",
                    data={"reason": "Verification budget exhausted before finding a reproducible delay."}
                )
                return VerificationConclusion(
                    status=VerificationStatus.INCONCLUSIVE,
                    reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                    reason_description="Exhausted verification budget.",
                    evidence_ids=[ev_id],
                    request_ids=successful_request_ids,
                    confidence=0
                )

            spec_sleep = build_injected_request(candidate, payload_set["sleep"])
            if not spec_sleep:
                continue
                
            resp_sleep = await send_safe(spec_sleep, is_sleep_test=True)
            if not resp_sleep:
                continue # Budget exceeded or non-timeout error
                
            if resp_sleep.duration_ms >= sleep_threshold:
                # 4. Control test
                spec_control = build_injected_request(candidate, payload_set["control"])
                resp_control = await send_safe(spec_control, is_sleep_test=False)
                
                if not resp_control:
                    continue # Control failed or timeout
                    
                if resp_control.duration_ms < control_threshold:
                    # 3. Reproducibility test
                    resp_sleep2 = await send_safe(spec_sleep, is_sleep_test=True)
                    if resp_sleep2 and resp_sleep2.duration_ms >= sleep_threshold:
                        # Confirmed!
                        ev_id = context.record_evidence(
                            evidence_type="time_delay_detected",
                            data={
                                "db_type": payload_set["db"],
                                "baseline_ms": baseline_duration,
                                "sleep_ms_1": resp_sleep.duration_ms,
                                "sleep_ms_2": resp_sleep2.duration_ms,
                                "control_ms": resp_control.duration_ms,
                                "payload_used": payload_set["sleep"]
                            },
                            request_id=resp_sleep2.request_id
                        )
                        return VerificationConclusion(
                            status=VerificationStatus.VERIFIED,
                            reason_code=VerificationReasonCode.REPRODUCED_SUCCESSFULLY,
                            reason_description=f"Reproducible time delay detected ({payload_set['db']} syntax).",
                            evidence_ids=[ev_id],
                            request_ids=successful_request_ids,
                            confidence=95
                        )

        # If we exhausted all payloads without confirming reproducibility
        ev_id = context.record_evidence(
            evidence_type="time_delay_failed",
            data={"reason": "No payloads produced a reliable, reproducible delay compared to control."}
        )
        return VerificationConclusion(
            status=VerificationStatus.INCONCLUSIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description="Could not reliably reproduce a time delay.",
            evidence_ids=[ev_id],
            request_ids=successful_request_ids,
            confidence=0
        )
