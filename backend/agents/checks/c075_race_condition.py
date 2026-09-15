"""C075 — Race Condition / Concurrency Vulnerability Check for AihaX."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C075RaceCondition(BaseCheck):
    contract = CheckContract(
        id="C075_Race_Condition",
        name="Race Condition / Concurrency Vulnerability",
        category=CheckCategory.BUSINESS_LOGIC,
        description="Detects concurrency flaws and race condition vulnerabilities where multiple simultaneous parallel requests (e.g. coupon redemption, balance transfer, password reset token consumption) succeed concurrently due to missing database locking.",
        severity=Severity.HIGH,
        vulnerability_type="Race Condition",
        cwe="CWE-362",
        owasp_category="A04:2021-Insecure Design",
        security_property="Critical state-modifying actions must enforce transaction isolation and distributed locking to prevent duplicate execution",
        remediation_guidance="Use database row-level locking (SELECT ... FOR UPDATE) or atomic operations/redis distributed mutexes for state transitions.",
        references=[
            "https://cwe.mitre.org/data/definitions/362.html",
            "https://portswigger.net/web-security/race-conditions",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "concurrent_successes"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        permit_testing = config.get("permit_race_condition_testing", False)
        if not permit_testing:
            return None

        # Send 3 concurrent requests simultaneously using asyncio.gather
        specs = [
            RequestSpec(
                url=target_url,
                method="POST",
                headers={"Content-Type": "application/json", "X-Concurrency-Probe": str(i)},
                body='{"action": "probe", "token": "aihax_concurrency_token_123"}',
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            for i in range(3)
        ]

        responses = await asyncio.gather(*[request_engine.execute(s) for s in specs], return_exceptions=True)
        successful_resps = [r for r in responses if not isinstance(r, Exception) and r.success and r.response_status in (200, 201)]

        # If all 3 concurrent requests succeeded with 200/201
        if len(successful_resps) == 3:
            req_ids = [r.request_id for r in successful_resps]
            ev_ids = [r.evidence_id for r in successful_resps]
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=Severity.HIGH,
                candidate_reason="3 simultaneous parallel state-modifying requests all succeeded with HTTP 200/201 without concurrency locking.",
                request_ids=req_ids,
                evidence_ids=ev_ids,
                observed_data={"concurrent_success_count": 3, "permit_race_condition_testing": permit_testing},
                payload="3x Parallel POST Request",
                proof_response="3 concurrent identical requests executed with status 200/201",
                confidence=75,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C075RaceCondition)
