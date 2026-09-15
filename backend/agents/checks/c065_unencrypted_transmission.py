"""C065 — Unencrypted Transmission of Sensitive Data Check for AihaX."""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urlparse, urlunparse

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C065UnencryptedTransmission(BaseCheck):
    contract = CheckContract(
        id="C065_Unencrypted_Transmission",
        name="Unencrypted Transmission of Sensitive Data",
        category=CheckCategory.SENSITIVE_DATA,
        description="Detects web applications that serve login, authentication, or sensitive endpoints over unencrypted HTTP (port 80) without enforcing a mandatory redirect to HTTPS.",
        severity=Severity.HIGH,
        vulnerability_type="Insecure Transport",
        cwe="CWE-319",
        owasp_category="A02:2021-Cryptographic Failures",
        security_property="All communication must be encrypted in transit using TLS/HTTPS",
        remediation_guidance="Configure web servers to redirect all HTTP traffic to HTTPS via permanent 301/308 redirects and enable HSTS.",
        references=[
            "https://cwe.mitre.org/data/definitions/319.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
        ],
        verification_strategy="transport_security",
        required_evidence=["affected_url", "proof_response", "http_status"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        parsed = urlparse(target_url)
        http_url = urlunparse(("http", parsed.netloc, parsed.path or "/", parsed.params, parsed.query, parsed.fragment))

        spec = RequestSpec(
            url=http_url,
            method="GET",
            follow_redirects=False,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp = await request_engine.execute(spec)
        if not resp.success:
            return None

        # If HTTP returns 200 OK without redirecting to HTTPS
        if resp.response_status == 200:
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=http_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=Severity.HIGH,
                candidate_reason=f"Application responds with HTTP 200 OK over unencrypted HTTP without redirecting to HTTPS.",
                request_ids=[resp.request_id],
                evidence_ids=[resp.evidence_id],
                observed_data={"http_url": http_url, "status": resp.response_status},
                payload=None,
                proof_response=f"Cleartext HTTP status: {resp.response_status} (No HTTPS redirect)",
                confidence=95,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C065UnencryptedTransmission)
