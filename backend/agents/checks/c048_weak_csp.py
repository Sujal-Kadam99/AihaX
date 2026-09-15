"""C048 — Weak Content Security Policy (CSP) Check for AihaX."""

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


class C048WeakCSP(BaseCheck):
    contract = CheckContract(
        id="C048_Weak_CSP",
        name="Weak Content Security Policy (CSP)",
        category=CheckCategory.MISCONFIG,
        description="Detects weakly configured Content Security Policies that permit 'unsafe-inline', 'unsafe-eval', or wildcard origins ('*') in script-src or default-src directives, effectively neutralizing XSS protection.",
        severity=Severity.LOW,
        vulnerability_type="Security Misconfiguration",
        cwe="CWE-1021",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="Content Security Policy must not declare unsafe-inline or wildcard sources in script execution contexts",
        remediation_guidance="Refactor inline scripts to external files with cryptographic nonces (nonce-...) or hashes (sha256-...) and remove 'unsafe-inline' and 'unsafe-eval'.",
        references=[
            "https://cwe.mitre.org/data/definitions/1021.html",
            "https://csp-evaluator.withgoogle.com/",
        ],
        verification_strategy="http_response_property",
        required_evidence=["affected_url", "proof_response", "csp_header"],
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

        headers_lower = {k.lower(): v for k, v in resp.response_headers.items()}
        csp = headers_lower.get("content-security-policy") or headers_lower.get("content-security-policy-report-only")
        if not csp:
            return None

        csp_lower = csp.lower()
        weaknesses = []
        if "'unsafe-inline'" in csp_lower and ("script-src" in csp_lower or "default-src" in csp_lower):
            weaknesses.append("'unsafe-inline' in script/default directives")
        if "'unsafe-eval'" in csp_lower:
            weaknesses.append("'unsafe-eval' in script directives")
        if "script-src *" in csp_lower or "default-src *" in csp_lower:
            weaknesses.append("wildcard '*' source in script/default directives")

        if weaknesses:
            weakness_desc = ", ".join(weaknesses)
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=Severity.LOW,
                candidate_reason=f"Content Security Policy contains high-risk directives: {weakness_desc}.",
                request_ids=[resp.request_id],
                evidence_ids=[resp.evidence_id],
                observed_data={"csp_header": csp, "weaknesses": weaknesses},
                payload=None,
                proof_response=f"CSP Header: {csp} [Weaknesses: {weakness_desc}]",
                confidence=95,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C048WeakCSP)
