"""C066 — Cleartext Sensitive Storage Indicators Check for AihaX."""

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


class C066CleartextStorageIndicators(BaseCheck):
    contract = CheckContract(
        id="C066_Cleartext_Storage_Indicators",
        name="Cleartext Sensitive Storage Indicators",
        category=CheckCategory.SENSITIVE_DATA,
        description="Detects client-side JavaScript that persists session tokens, JWTs, or passwords directly into localStorage or sessionStorage, exposing tokens to exfiltration via XSS.",
        severity=Severity.LOW,
        vulnerability_type="Insecure Storage",
        cwe="CWE-312",
        owasp_category="A04:2021-Insecure Design",
        security_property="Authentication and session tokens should be stored in HttpOnly cookies rather than client-accessible Web Storage",
        remediation_guidance="Store authentication tokens in Secure, HttpOnly cookies instead of browser localStorage or sessionStorage.",
        references=[
            "https://cwe.mitre.org/data/definitions/312.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "storage_pattern"],
        destructive=False,
    )

    STORAGE_PATTERNS = [
        re.compile(r"localStorage\.setItem\s*\(\s*['\"](?:token|jwt|auth|access_token|bearer|password)['\"]", re.I),
        re.compile(r"sessionStorage\.setItem\s*\(\s*['\"](?:token|jwt|auth|access_token|bearer|password)['\"]", re.I),
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
        for pat in self.STORAGE_PATTERNS:
            match = pat.search(body)
            if match:
                snippet = body[max(0, match.start() - 10) : min(len(body), match.end() + 30)].strip()
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=target_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.LOW,
                    candidate_reason=f"Client JavaScript stores sensitive authentication tokens in browser Web Storage: '{snippet}'.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"snippet": snippet},
                    payload=None,
                    proof_response=f"Web Storage Pattern Found: {snippet}",
                    confidence=90,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C066CleartextStorageIndicators)
