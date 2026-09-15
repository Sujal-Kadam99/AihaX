"""C021 — JWT Claim Validation Weakness Check for AihaX."""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict, Optional

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import AuthenticationContext, RequestEngine, RequestSpec, RequestTimeout


def _b64url_encode(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("utf-8")


class C021JWTClaimValidationWeakness(BaseCheck):
    contract = CheckContract(
        id="C021_JWT_Claim_Validation",
        name="JWT Claim Validation Weakness",
        category=CheckCategory.AUTH,
        description="Detects failure to enforce standard JWT claims, specifically missing expiration ('exp') claim enforcement, allowing permanently valid or expired session replay.",
        severity=Severity.HIGH,
        vulnerability_type="Insecure JWT Validation",
        cwe="CWE-672",
        owasp_category="A07:2021-Identification and Authentication Failures",
        security_property="JWT tokens must strictly validate the 'exp' (expiration) and 'nbf' (not before) standard claims",
        remediation_guidance="Ensure JWT verification libraries validate token expiration (verify_exp=True) with minimal clock skew allowance.",
        references=[
            "https://cwe.mitre.org/data/definitions/672.html",
            "https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4",
        ],
        verification_strategy="authentication_comparison",
        required_evidence=["affected_url", "proof_response", "expired_token"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        # Step 1: Baseline unauthenticated request
        base_spec = RequestSpec(
            url=target_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        base_resp = await request_engine.execute(base_spec)
        if not base_resp.success:
            return None

        # Step 2: Invalid token control probe
        invalid_ctx = AuthenticationContext(
            name="Invalid-Token-Control",
            headers={"Authorization": "Bearer invalid.garbage.token123"},
        )
        invalid_spec = RequestSpec(
            url=target_url,
            method="GET",
            auth_context=invalid_ctx,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        invalid_resp = await request_engine.execute(invalid_spec)

        # Step 3: Construct expired JWT token with exp in the year 2020
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "user_audit", "exp": 1577836800, "iat": 1577833200}  # Jan 1, 2020
        dummy_sig = "dummysignaturemockevidencehash123456"
        expired_jwt = f"{_b64url_encode(header)}.{_b64url_encode(payload)}.{dummy_sig}"

        auth_ctx = AuthenticationContext(
            name="JWT-Expired-Claim-Test",
            headers={"Authorization": f"Bearer {expired_jwt}"},
        )
        spec = RequestSpec(
            url=target_url,
            method="GET",
            auth_context=auth_ctx,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp = await request_engine.execute(spec)
        if not resp.success:
            return None

        # True vulnerability: Either baseline or invalid token is 401/403 (proving token gating exists),
        # but the expired token is accepted with HTTP 200 OK
        is_token_gated = (base_resp.response_status in (401, 403)) or (invalid_resp.success and invalid_resp.response_status in (401, 403))
        if resp.response_status == 200 and is_token_gated:
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=Severity.HIGH,
                candidate_reason="Target requires authentication but accepted an expired JWT token (exp: 2020-01-01) with HTTP 200 OK.",
                request_ids=[r.request_id for r in [base_resp, resp] if r],
                evidence_ids=[r.evidence_id for r in [base_resp, resp] if r],
                observed_data={"expired_token": expired_jwt, "status": resp.response_status, "baseline_status": base_resp.response_status},
                payload=f"Bearer {expired_jwt}",
                proof_response=f"HTTP {resp.response_status} with expired exp claim: {(resp.response_body or '')[:200]}",
                confidence=85,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C021JWTClaimValidationWeakness)
