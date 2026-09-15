"""C022 — Authentication Rate-Limit Weakness Check for AihaX."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional
from urllib.parse import urljoin

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C022AuthRateLimitWeakness(BaseCheck):
    contract = CheckContract(
        id="C022_Auth_Rate_Limit",
        name="Authentication Rate-Limit Weakness",
        category=CheckCategory.AUTH,
        description="Detects missing rate-limiting or brute-force protection on authentication and credential endpoints, permitting unthrottled password guessing attacks.",
        severity=Severity.MEDIUM,
        vulnerability_type="Missing Rate Limiting",
        cwe="CWE-307",
        owasp_category="A07:2021-Identification and Authentication Failures",
        security_property="Authentication endpoints must enforce rate limits (e.g. max 5 attempts/min) or CAPTCHA triggers to mitigate brute force",
        remediation_guidance="Implement IP and account-based rate limiting (e.g. returning HTTP 429 Too Many Requests) and account lockout/CAPTCHA after failed attempts.",
        references=[
            "https://cwe.mitre.org/data/definitions/307.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#login-throttling",
        ],
        verification_strategy="auth_rate_limit",
        required_evidence=["affected_url", "proof_response", "consecutive_attempts"],
        destructive=False,
    )

    LOGIN_PATHS = ["/login", "/api/login", "/api/auth/login", "/auth/login", "/api/v1/auth/login"]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        base = target_url.rstrip("/")

        for path in self.LOGIN_PATHS:
            login_url = urljoin(base + "/", path.lstrip("/"))
            payload = json.dumps({"username": "aihax_test_user@example.com", "password": "wrong_password_probe"})

            consecutive_statuses = []
            requests_made = []
            evidences = []

            # Send 5 rapid authentication attempts
            for i in range(5):
                spec = RequestSpec(
                    url=login_url,
                    method="POST",
                    headers={"Content-Type": "application/json"},
                    body=payload,
                    timeout=RequestTimeout(connect=3.0, read=5.0, total=8.0),
                )
                resp = await request_engine.execute(spec)
                if not resp.success:
                    break

                consecutive_statuses.append(resp.response_status)
                requests_made.append(resp.request_id)
                evidences.append(resp.evidence_id)

            # If all 5 requests completed without encountering 429 (Too Many Requests) or lockout
            if len(consecutive_statuses) == 5 and all(s in (200, 400, 401) for s in consecutive_statuses):
                # Ensure endpoint actually exists (not 404)
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=login_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.MEDIUM,
                    candidate_reason=f"Login endpoint '{login_url}' allowed 5 consecutive rapid authentication attempts without rate-limiting (all returned HTTP {consecutive_statuses[0]}).",
                    request_ids=requests_made,
                    evidence_ids=evidences,
                    observed_data={"endpoint": login_url, "statuses": consecutive_statuses},
                    payload="5 consecutive login attempts",
                    proof_response=f"5 consecutive attempts returned statuses: {consecutive_statuses} (No HTTP 429 triggered)",
                    confidence=75,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C022AuthRateLimitWeakness)
