"""C001 — Open Port / HTTP Exposure Check for AihaX."""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urlparse

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C001OpenPort80(BaseCheck):
    contract = CheckContract(
        id="C001_Open_Port_80",
        name="Open Port / HTTP Exposure",
        category=CheckCategory.RECON,
        description="Detects whether an unencrypted HTTP port (e.g. port 80) is open and responding without strict HTTPS enforcement.",
        severity=Severity.INFO,
        vulnerability_type="Insecure Transport",
        cwe="CWE-319",
        owasp_category="A02:2021-Cryptographic Failures",
        security_property="Cleartext HTTP service must enforce immediate redirect to TLS/HTTPS",
        remediation_guidance="Configure web server to permanently redirect all HTTP traffic (port 80) to HTTPS (port 443) using 301 or 308 redirects.",
        references=["https://cwe.mitre.org/data/definitions/319.html"],
        verification_strategy="transport_security",
        required_evidence=["affected_url", "proof_response"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        # Formulate non-destructive HTTP port request
        parsed = urlparse(target_url)
        http_target = f"http://{parsed.netloc or parsed.path.split('/')[0]}"
        if not http_target.startswith("http://"):
            http_target = f"http://{http_target}"

        spec = RequestSpec(
            url=http_target,
            method="GET",
            follow_redirects=False,
            timeout=RequestTimeout(connect=4.0, read=5.0, total=8.0),
        )

        resp_evidence = await request_engine.execute(spec)
        if not resp_evidence.success:
            return None

        # Check if HTTP responds directly with 200 without redirecting to HTTPS
        if resp_evidence.response_status in (200, 204) or (
            resp_evidence.response_status in (301, 302, 307, 308)
            and not str(resp_evidence.response_headers.get("location", "")).lower().startswith("https://")
        ):
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=http_target,
                affected_url=http_target,
                vulnerability_type=self.contract.vulnerability_type,
                severity=self.contract.severity,
                candidate_reason=f"HTTP service on port 80 returned status {resp_evidence.response_status} without immediate HTTPS enforcement.",
                request_ids=[resp_evidence.request_id],
                evidence_ids=[resp_evidence.evidence_id],
                observed_data={
                    "status_code": resp_evidence.response_status,
                    "location_header": resp_evidence.response_headers.get("location"),
                    "server_header": resp_evidence.response_headers.get("server"),
                },
                proof_response=f"HTTP/1.1 {resp_evidence.response_status}\r\n" + "\r\n".join(
                    f"{k}: {v}" for k, v in list(resp_evidence.response_headers.items())[:5]
                ),
                confidence=60,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C001OpenPort80)
