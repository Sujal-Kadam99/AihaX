"""C020 — JWT Algorithm / Configuration Weakness Check for AihaX."""

from __future__ import annotations

import base64
import json
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


class C020JWTAlgorithmWeakness(BaseCheck):
    contract = CheckContract(
        id="C020_JWT_Algorithm_Weakness",
        name="JWT Algorithm / Configuration Weakness",
        category=CheckCategory.AUTH,
        description="Detects whether JWT verification accepts the insecure 'none' algorithm or unsigned tokens, permitting complete signature forgery.",
        severity=Severity.CRITICAL,
        vulnerability_type="Insecure JWT Configuration",
        cwe="CWE-347",
        owasp_category="A02:2021-Cryptographic Failures",
        security_property="JWT tokens must enforce a verified cryptographic signature and reject 'none' or unsigned algorithms",
        remediation_guidance="Explicitly configure JWT verification libraries to only accept trusted cryptographic algorithms (e.g. RS256, HS256) and reject alg: none.",
        references=[
            "https://cwe.mitre.org/data/definitions/347.html",
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
        ],
        verification_strategy="authentication_comparison",
        required_evidence=["affected_url", "proof_response", "forged_token"],
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

        # Step 3: Construct an unsigned alg: none JWT
        header = {"alg": "none", "typ": "JWT"}
        payload = {"sub": "admin", "role": "admin", "admin": True, "iat": 1516239022}
        none_jwt = f"{_b64url_encode(header)}.{_b64url_encode(payload)}."

        auth_ctx = AuthenticationContext(
            name="JWT-None-Alg-Test",
            headers={"Authorization": f"Bearer {none_jwt}"},
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

        # True vulnerability: Either baseline is 401/403 or invalid token is 401/403 (proving token validation exists),
        # but the unsigned alg: none token is accepted with HTTP 200 OK
        is_token_gated = (base_resp.response_status in (401, 403)) or (invalid_resp.success and invalid_resp.response_status in (401, 403))
        if resp.response_status == 200 and is_token_gated:
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=Severity.CRITICAL,
                candidate_reason=f"Target requires authentication (rejected invalid token with {invalid_resp.response_status if invalid_resp.success else base_resp.response_status}) but accepted an unsigned JWT with 'alg: none' yielding HTTP 200 OK.",
                request_ids=[r.request_id for r in [base_resp, resp] if r],
                evidence_ids=[r.evidence_id for r in [base_resp, resp] if r],
                observed_data={"token": none_jwt, "status": resp.response_status, "baseline_status": base_resp.response_status},
                payload=f"Bearer {none_jwt}",
                proof_response=f"HTTP {resp.response_status} with alg: none token: {(resp.response_body or '')[:200]}",
                confidence=95,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C020JWTAlgorithmWeakness)
