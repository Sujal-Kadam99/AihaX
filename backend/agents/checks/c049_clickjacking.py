"""C049 — Clickjacking / Missing Frame Options Check for AihaX."""

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


class C049Clickjacking(BaseCheck):
    contract = CheckContract(
        id="C049_Clickjacking",
        name="Clickjacking / Missing Frame Options",
        category=CheckCategory.MISCONFIG,
        description="Detects missing Clickjacking defenses (missing X-Frame-Options header and missing CSP frame-ancestors directive) allowing the target page to be framed inside an attacker's iframe overlay.",
        severity=Severity.MEDIUM,
        vulnerability_type="Security Misconfiguration",
        cwe="CWE-1021",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="HTML pages must enforce framing restrictions using X-Frame-Options or frame-ancestors",
        remediation_guidance="Send 'X-Frame-Options: DENY' (or 'SAMEORIGIN') or include 'frame-ancestors 'self'' in Content-Security-Policy.",
        references=[
            "https://cwe.mitre.org/data/definitions/1021.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
        ],
        verification_strategy="http_response_property",
        required_evidence=["affected_url", "proof_response", "framing_headers"],
        destructive=False,
    )

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

        content_type = resp.response_headers.get("content-type", "").lower()
        if "html" not in content_type and content_type:
            return None

        headers_lower = {k.lower(): v for k, v in resp.response_headers.items()}
        xfo = headers_lower.get("x-frame-options", "").lower()
        csp = headers_lower.get("content-security-policy", "").lower()

        has_xfo = xfo in ("deny", "sameorigin")
        has_frame_ancestors = "frame-ancestors" in csp

        if not has_xfo and not has_frame_ancestors:
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=Severity.MEDIUM,
                candidate_reason="HTML response omits both 'X-Frame-Options' and CSP 'frame-ancestors' directives, permitting iframe embedding.",
                request_ids=[resp.request_id],
                evidence_ids=[resp.evidence_id],
                observed_data={"content_type": content_type, "x_frame_options": xfo, "csp": csp},
                payload=None,
                proof_response="Missing X-Frame-Options and frame-ancestors in response headers",
                confidence=95,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C049Clickjacking)
