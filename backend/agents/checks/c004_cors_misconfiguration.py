"""C004 — CORS Misconfiguration Check for AihaX."""

from __future__ import annotations

from typing import Any, Dict, Optional

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C004CORSMisconfiguration(BaseCheck):
    contract = CheckContract(
        id="C004_CORS_Misconfiguration",
        name="CORS Misconfiguration",
        category=CheckCategory.RECON,
        description="Detects overly permissive Cross-Origin Resource Sharing policies, such as arbitrary Origin reflection or wildcard trust with credentials.",
        severity=Severity.MEDIUM,
        vulnerability_type="Cross-Origin Misconfiguration",
        cwe="CWE-346",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="cross-origin behavior does not permit unauthorized credentialed access",
        remediation_guidance="Specify explicit trusted origin domains in Access-Control-Allow-Origin rather than reflecting arbitrary request origins or using wildcards with credentials.",
        references=["https://portswigger.net/web-security/cors"],
        verification_strategy="cors_misconfiguration",
        required_evidence=["affected_url", "origin_header", "acao_header"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        untrusted_origin = "https://evil.com"
        spec = RequestSpec(
            url=target_url,
            method="GET",
            headers={"Origin": untrusted_origin},
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        resp_evidence = await request_engine.execute(spec)
        if not resp_evidence.success:
            return None

        headers_lower = {k.lower(): v for k, v in resp_evidence.response_headers.items()}
        acao = headers_lower.get("access-control-allow-origin", "")
        acac = headers_lower.get("access-control-allow-credentials", "").lower() == "true"

        # Meaningful candidate condition: ACAO is wildcard or reflects untrusted origin
        if acao and ("evil.com" in acao or acao == "*" or acao == "null"):
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=Severity.HIGH if acac and "evil.com" in acao else Severity.MEDIUM,
                candidate_reason=(
                    f"Server responded with Access-Control-Allow-Origin: '{acao}' when supplied with untrusted Origin '{untrusted_origin}'"
                    + (" and Access-Control-Allow-Credentials: true." if acac else ".")
                ),
                request_ids=[resp_evidence.request_id],
                evidence_ids=[resp_evidence.evidence_id],
                observed_data={
                    "request_origin": untrusted_origin,
                    "access_control_allow_origin": acao,
                    "access_control_allow_credentials": acac,
                    "response_status": resp_evidence.response_status,
                },
                payload=f"Origin: {untrusted_origin}",
                proof_response=f"Access-Control-Allow-Origin: {acao}\r\nAccess-Control-Allow-Credentials: {acac}",
                confidence=75,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C004CORSMisconfiguration)
