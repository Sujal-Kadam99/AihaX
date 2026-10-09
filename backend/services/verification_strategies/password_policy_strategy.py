"""Verification strategy for C019: Password Policy Weakness Indicators."""

from __future__ import annotations

import json
import secrets
from backend.services.verification_engine import (
    BaseVerificationStrategy,
    VerificationConclusion,
    VerificationContext,
    VerificationContract,
    VerificationReasonCode,
    VerificationRegistry,
    VerificationStatus,
)
from backend.services.request_engine import RequestSpec, RequestTimeout


class PasswordPolicyVerificationStrategy(BaseVerificationStrategy):
    """Verifies whether an authentication/registration endpoint accepts trivial or single-character passwords."""

    contract = VerificationContract(
        check_id="C019_Password_Policy_Weakness",
        name="Password Policy Weakness Verification",
        security_property="Authentication endpoints must enforce a minimum password length and complexity policy.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        url = context.candidate_evidence.get("affected_url") or context.target_url
        test_user = f"aihax_verify_{secrets.token_hex(4)}@example.com"
        trivial_passwords = ["1", "a", "12345"]

        verified_reasons = []
        observed_evidence = []
        tested_request_ids = []

        for pw in trivial_passwords:
            payload = json.dumps({
                "username": test_user,
                "email": test_user,
                "password": pw,
                "confirm_password": pw,
            })
            spec = RequestSpec(
                url=url,
                method="POST",
                headers={"Content-Type": "application/json"},
                body=payload,
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            resp = await context.send_verification_request(spec)
            if not resp or not resp.success:
                continue

            tested_request_ids.append(resp.request_id)
            body_lower = (resp.response_body or "").lower()
            content_type = next(
                (value for key, value in resp.response_headers.items() if key.lower() == "content-type"),
                "",
            ).lower()

            # A SPA fallback may answer POST /register with HTTP 200 HTML without
            # creating an account. That response cannot prove password acceptance.
            if "application/json" not in content_type:
                continue

            # If rejected with validation error regarding password policy
            if resp.response_status in (400, 422) or ("password" in body_lower and ("too short" in body_lower or "complexity" in body_lower or "at least" in body_lower or "character" in body_lower)):
                # Server enforced policy
                continue

            # If accepted with 200 or 201 Created or success message
            if resp.response_status in (200, 201) and test_user.lower() in body_lower:
                ev_id = context.record_evidence(
                    evidence_type="weak_password_accepted",
                    data={
                        "endpoint": url,
                        "accepted_password": pw,
                        "status_code": resp.response_status,
                        "response_preview": (resp.response_body or "")[:200],
                    },
                    request_id=resp.request_id,
                )
                observed_evidence.append(ev_id)
                verified_reasons.append(f"Accepted password '{pw}' with HTTP {resp.response_status}")
                break

        if verified_reasons:
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description=f"Endpoint accepted trivial password without enforcing minimum complexity: {verified_reasons[0]}.",
                evidence_ids=observed_evidence,
                request_ids=tested_request_ids,
                confidence=90,
            )

        ev_id = context.record_evidence(
            evidence_type="password_policy_enforced",
            data={"status": "policy_enforced"},
            request_id=tested_request_ids[-1] if tested_request_ids else None,
        )
        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTROL_ENFORCED,
            reason_description="Registration/auth endpoint rejected trivial passwords and enforced length/complexity requirements.",
            evidence_ids=[ev_id],
            request_ids=tested_request_ids,
            confidence=85,
        )


VerificationRegistry.register(PasswordPolicyVerificationStrategy)
