"""C019 — Password Policy Weakness Indicators Check for AihaX."""

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


class C019PasswordPolicyWeakness(BaseCheck):
    contract = CheckContract(
        id="C019_Password_Policy_Weakness",
        name="Password Policy Weakness Indicators",
        category=CheckCategory.AUTH,
        description="Detects whether registration or password update endpoints accept trivial passwords (e.g. '1', 'password', '123456') without enforcing minimal complexity or length standards.",
        severity=Severity.LOW,
        vulnerability_type="Weak Password Policy",
        cwe="CWE-521",
        owasp_category="A07:2021-Identification and Authentication Failures",
        security_property="Authentication endpoints must enforce a robust password policy (minimum length >= 8 characters)",
        remediation_guidance="Enforce minimum password length (at least 8–12 characters) and reject commonly compromised passwords.",
        references=[
            "https://cwe.mitre.org/data/definitions/521.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#password-complexity",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "tested_weak_password"],
        destructive=False,
    )

    REG_PATHS = ["/api/register", "/api/signup", "/register", "/signup", "/api/auth/register"]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        base = target_url.rstrip("/")
        weak_payload = json.dumps({
            "username": "aihax_audit_test_user@example.com",
            "email": "aihax_audit_test_user@example.com",
            "password": "1",  # Trivial password
        })

        for path in self.REG_PATHS:
            reg_url = urljoin(base + "/", path.lstrip("/"))
            spec = RequestSpec(
                url=reg_url,
                method="POST",
                headers={"Content-Type": "application/json"},
                body=weak_payload,
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            resp = await request_engine.execute(spec)
            if not resp.success:
                continue

            # If the server accepts the registration with 200/201 without rejecting password length
            if resp.response_status in (200, 201) and "password" not in (resp.response_body or "").lower():
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=reg_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.LOW,
                    candidate_reason=f"Registration endpoint '{reg_url}' accepted trivial single-character password ('1') with HTTP {resp.response_status}.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"endpoint": reg_url, "status": resp.response_status},
                    payload="password: '1'",
                    proof_response=f"HTTP {resp.response_status} with body: {(resp.response_body or '')[:200]}",
                    confidence=80,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C019PasswordPolicyWeakness)
