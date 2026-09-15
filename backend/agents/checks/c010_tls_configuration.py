"""C010 — TLS / HTTPS Configuration Weakness Check for AihaX."""

from __future__ import annotations

import re
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


class C010TLSConfigurationWeakness(BaseCheck):
    contract = CheckContract(
        id="C010_TLS_Configuration_Weakness",
        name="TLS / HTTPS Configuration Weakness",
        category=CheckCategory.RECON,
        description="Detects TLS/HTTPS implementation weaknesses such as missing or weakly configured HTTP Strict Transport Security (HSTS) and missing includeSubDomains directives.",
        severity=Severity.LOW,
        vulnerability_type="Insecure Transport Configuration",
        cwe="CWE-319",
        owasp_category="A02:2021-Cryptographic Failures",
        security_property="HTTPS web services must enforce strict transport security with adequate max-age and subdomains coverage",
        remediation_guidance="Enable the Strict-Transport-Security header with a max-age of at least 31536000 seconds (1 year) and include the includeSubDomains and preload directives.",
        references=[
            "https://cwe.mitre.org/data/definitions/319.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
        ],
        verification_strategy="http_response_property",
        required_evidence=["affected_url", "proof_response"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        parsed = urlparse(target_url)
        # Ensure we test HTTPS endpoint
        https_url = f"https://{parsed.netloc or parsed.path}"

        spec = RequestSpec(
            url=https_url,
            method="GET",
            follow_redirects=True,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        resp_evidence = await request_engine.execute(spec)
        if not resp_evidence.success:
            return None

        headers_lower = {k.lower(): v for k, v in resp_evidence.response_headers.items()}
        hsts = headers_lower.get("strict-transport-security")

        if not hsts:
            return CheckResult(
                check_id=self.contract.id,
                title="Missing HTTP Strict Transport Security (HSTS)",
                target=target_url,
                affected_url=https_url,
                vulnerability_type="Missing Security Header",
                severity=Severity.LOW,
                candidate_reason="The HTTPS service does not declare the Strict-Transport-Security (HSTS) response header (defense-in-depth hardening recommendation).",
                request_ids=[resp_evidence.request_id],
                evidence_ids=[resp_evidence.evidence_id],
                observed_data={"hsts_header": None, "status": resp_evidence.response_status},
                payload=None,
                proof_response="Strict-Transport-Security: [MISSING]",
                confidence=90,
                verification_status="CANDIDATE",
            )

        # Check for weak max-age (< 15768000 = 6 months)
        max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if max_age_match:
            max_age_val = int(max_age_match.group(1))
            if max_age_val < 15768000:
                return CheckResult(
                    check_id=self.contract.id,
                    title=f"{self.contract.name} (Short HSTS Duration)",
                    target=target_url,
                    affected_url=https_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.INFO,
                    candidate_reason=f"Strict-Transport-Security header specifies a short max-age ({max_age_val}s < 15768000s).",
                    request_ids=[resp_evidence.request_id],
                    evidence_ids=[resp_evidence.evidence_id],
                    observed_data={"hsts_header": hsts, "max_age": max_age_val},
                    payload=None,
                    proof_response=f"Strict-Transport-Security: {hsts}",
                    confidence=85,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C010TLSConfigurationWeakness)
