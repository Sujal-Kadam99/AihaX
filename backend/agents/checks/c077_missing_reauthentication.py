"""C077 — Missing Re-Authentication on Sensitive Actions Check for AihaX."""

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
from backend.services.request_engine import AuthenticationContext, RequestEngine, RequestSpec, RequestTimeout


class C077MissingReauthentication(BaseCheck):
    contract = CheckContract(
        id="C077_Missing_Reauthentication",
        name="Missing Re-Authentication on Sensitive Actions",
        category=CheckCategory.BUSINESS_LOGIC,
        description="Detects critical account actions (password modification, email update, 2FA deactivation) that fail to require the user's current password or step-up re-authentication before executing changes.",
        severity=Severity.MEDIUM,
        vulnerability_type="Broken Access Control",
        cwe="CWE-306",
        owasp_category="A07:2021-Identification and Authentication Failures",
        security_property="Sensitive account modifications must require verification of the user's current password or step-up authentication",
        remediation_guidance="Require confirmation of current password before allowing password, email, or MFA security setting updates.",
        references=[
            "https://cwe.mitre.org/data/definitions/306.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
        ],
        verification_strategy="authorization_comparison",
        required_evidence=["affected_url", "proof_response", "sensitive_endpoint"],
        destructive=False,
    )

    SENSITIVE_ACTIONS = [
        ("/api/user/change-password", {"new_password": "NewSecurePassword123!"}),
        ("/api/user/update-email", {"email": "new_email_test@example.com"}),
        ("/api/account/password", {"new_password": "NewSecurePassword123!"}),
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        auth_token = config.get("auth_token") or config.get("user_token")
        auth_ctx = None
        if auth_token:
            auth_ctx = AuthenticationContext(
                name="ReAuthTestUser",
                headers={"Authorization": f"Bearer {auth_token}"},
            )

        base = target_url.rstrip("/")
        for path, body_dict in self.SENSITIVE_ACTIONS:
            action_url = urljoin(base + "/", path.lstrip("/"))
            spec = RequestSpec(
                url=action_url,
                method="POST",
                auth_context=auth_ctx,
                headers={"Content-Type": "application/json"},
                body=json.dumps(body_dict),
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            resp = await request_engine.execute(spec)
            if not resp.success:
                continue

            # If the sensitive action succeeds with 200 without requiring "current_password"
            if resp.response_status in (200, 201) and "current_password" not in (resp.response_body or "").lower():
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=action_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.MEDIUM,
                    candidate_reason=f"Sensitive account endpoint '{action_url}' processed update with HTTP {resp.response_status} without requiring current password re-authentication.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"endpoint": action_url, "status": resp.response_status},
                    payload=json.dumps(body_dict),
                    proof_response=f"Update processed without current password check (HTTP {resp.response_status})",
                    confidence=80,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C077MissingReauthentication)
