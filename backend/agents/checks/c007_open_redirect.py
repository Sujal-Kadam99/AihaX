"""C007 — Open Redirect Check for AihaX."""

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


class C007OpenRedirect(BaseCheck):
    contract = CheckContract(
        id="C007_Open_Redirect",
        name="Open Redirect",
        category=CheckCategory.RECON,
        description="Detects whether unvalidated user-controlled redirect parameters allow redirection to an unauthorized external destination.",
        severity=Severity.MEDIUM,
        vulnerability_type="Open Redirect",
        cwe="CWE-601",
        owasp_category="A01:2021-Broken Access Control",
        security_property="user-controlled redirect destination is not allowed to redirect to an unauthorized external destination",
        remediation_guidance="Validate all redirect destinations against an explicit allowlist of trusted domains or enforce relative URL redirection exclusively.",
        references=["https://cwe.mitre.org/data/definitions/601.html"],
        verification_strategy="open_redirect",
        required_evidence=["affected_url", "redirect_param", "proof_response"],
        destructive=False,
    )

    REDIRECT_PARAMS = ["next", "redirect", "url", "dest", "target", "r"]
    UNTRUSTED_DESTINATION = "https://evil.com"

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        base = target_url.rstrip("/")

        for param in self.REDIRECT_PARAMS:
            delim = "&" if "?" in base else "?"
            test_url = f"{base}{delim}{param}={self.UNTRUSTED_DESTINATION}"

            spec = RequestSpec(
                url=test_url,
                method="GET",
                follow_redirects=False,
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )

            resp_evidence = await request_engine.execute(spec)
            if not resp_evidence.success:
                continue

            # Candidate condition: 3xx status code AND Location header points to untrusted destination
            headers_lower = {k.lower(): v for k, v in resp_evidence.response_headers.items()}
            location = headers_lower.get("location", "")
            if resp_evidence.response_status in (301, 302, 303, 307, 308) and location:
                if location.startswith(self.UNTRUSTED_DESTINATION) or "evil.com" in location.lower():
                    return CheckResult(
                        check_id=self.contract.id,
                        title=self.contract.name,
                        target=test_url,
                        affected_url=test_url,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=self.contract.severity,
                        candidate_reason=f"Parameter '{param}' triggered HTTP {resp_evidence.response_status} redirect to external domain '{location}'.",
                        request_ids=[resp_evidence.request_id],
                        evidence_ids=[resp_evidence.evidence_id],
                        observed_data={
                            "param": param,
                            "destination": self.UNTRUSTED_DESTINATION,
                            "status_code": resp_evidence.response_status,
                            "location_header": location,
                        },
                        affected_param=param,
                        payload=f"{param}={self.UNTRUSTED_DESTINATION}",
                        proof_response=f"HTTP/1.1 {resp_evidence.response_status} Redirect\r\nLocation: {location}",
                        confidence=85,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C007OpenRedirect)
