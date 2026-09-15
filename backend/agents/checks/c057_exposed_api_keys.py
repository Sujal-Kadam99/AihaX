"""C057 — Hardcoded API Keys / Secrets Exposed Check for AihaX."""

from __future__ import annotations

import re
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


class C057ExposedAPIKeys(BaseCheck):
    contract = CheckContract(
        id="C057_Exposed_API_Keys",
        name="Hardcoded API Keys / Secrets Exposed",
        category=CheckCategory.SENSITIVE_DATA,
        description="Detects high-entropy secrets and hardcoded API tokens (AWS access keys, Stripe live keys, GitHub tokens, Slack tokens, private RSA keys) exposed in public responses or client-side JavaScript bundles.",
        severity=Severity.HIGH,
        vulnerability_type="Information Disclosure",
        cwe="CWE-798",
        owasp_category="A07:2021-Identification and Authentication Failures",
        security_property="Cryptographic keys, cloud credentials, and secret tokens must never be embedded in public client code or responses",
        remediation_guidance="Revoke exposed credentials immediately, rotate keys, and migrate secret references to secure backend environment variables or secrets vaults.",
        references=[
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
        ],
        verification_strategy="sensitive_file_exposure",
        required_evidence=["affected_url", "proof_response", "secret_type"],
        destructive=False,
    )

    SECRET_PATTERNS = [
        ("AWS Access Key ID", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
        ("Stripe Live Secret Key", re.compile(r"\b(sk_live_[0-9a-zA-Z]{24})\b")),
        ("GitHub Personal Access Token", re.compile(r"\b(ghp_[0-9a-zA-Z]{36})\b")),
        ("Slack Token", re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b")),
        ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        spec = RequestSpec(
            url=target_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp = await request_engine.execute(spec)
        if not resp.success:
            return None

        body = resp.response_body or ""
        for secret_name, pat in self.SECRET_PATTERNS:
            match = pat.search(body)
            if match:
                raw_match = match.group(0)
                # Redact middle characters for safe proof display
                if len(raw_match) > 8:
                    redacted = raw_match[:4] + "*" * (len(raw_match) - 8) + raw_match[-4:]
                else:
                    redacted = raw_match[:2] + "****"

                return CheckResult(
                    check_id=self.contract.id,
                    title=f"{self.contract.name} ({secret_name})",
                    target=target_url,
                    affected_url=target_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.HIGH,
                    candidate_reason=f"Exposed secret token pattern ({secret_name}) detected in response: '{redacted}'.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"secret_type": secret_name, "redacted_token": redacted},
                    payload=None,
                    proof_response=f"Secret Match ({secret_name}): {redacted}",
                    confidence=95,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C057ExposedAPIKeys)
