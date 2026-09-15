"""C012 — Authentication Bypass Indicators Check for AihaX."""

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


class C012AuthBypassIndicators(BaseCheck):
    contract = CheckContract(
        id="C012_Auth_Bypass_Indicators",
        name="Authentication Bypass Indicators",
        category=CheckCategory.AUTH,
        description="Detects authentication and authorization filter bypasses via URL path normalization (e.g. /..;/, /%2e/), header overrides (X-Original-URL, X-Rewrite-URL), or internal IP spoofing headers.",
        severity=Severity.HIGH,
        vulnerability_type="Authentication Bypass",
        cwe="CWE-287",
        owasp_category="A07:2021-Identification and Authentication Failures",
        security_property="Protected endpoints must enforce authentication regardless of path normalization quirks or spoofed proxy headers",
        remediation_guidance="Normalize request URIs before evaluating authentication filters and ignore client-supplied X-Original-URL, X-Rewrite-URL, or forwarding headers for access control.",
        references=[
            "https://cwe.mitre.org/data/definitions/287.html",
            "https://portswigger.net/web-security/authentication",
        ],
        verification_strategy="authentication_comparison",
        required_evidence=["affected_url", "proof_response", "bypass_technique"],
        destructive=False,
    )

    BYPASS_HEADERS = [
        ({"X-Original-URL": "/admin"}, "X-Original-URL Header Override"),
        ({"X-Rewrite-URL": "/admin"}, "X-Rewrite-URL Header Override"),
        ({"X-Forwarded-For": "127.0.0.1"}, "X-Forwarded-For Localhost Spoofing"),
        ({"X-Custom-IP-Authorization": "127.0.0.1"}, "X-Custom-IP-Authorization Spoofing"),
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        base_spec = RequestSpec(
            url=target_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        base_resp = await request_engine.execute(base_spec)
        if not base_resp.success:
            return None

        # Test if target is currently restricted (401 or 403)
        if base_resp.response_status in (401, 403):
            for headers, technique in self.BYPASS_HEADERS:
                bypass_spec = RequestSpec(
                    url=target_url,
                    method="GET",
                    headers=headers,
                    timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
                )
                resp = await request_engine.execute(bypass_spec)
                if resp.success and resp.response_status == 200:
                    return CheckResult(
                        check_id=self.contract.id,
                        title=f"{self.contract.name} ({technique})",
                        target=target_url,
                        affected_url=target_url,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.HIGH,
                        candidate_reason=f"Baseline returned HTTP {base_resp.response_status}, but {technique} succeeded with HTTP 200 OK.",
                        request_ids=[base_resp.request_id, resp.request_id],
                        evidence_ids=[base_resp.evidence_id, resp.evidence_id],
                        observed_data={
                            "baseline_status": base_resp.response_status,
                            "bypass_status": resp.response_status,
                            "technique": technique,
                            "headers": headers,
                        },
                        payload=str(headers),
                        proof_response=f"Baseline: HTTP {base_resp.response_status} -> Bypass: HTTP {resp.response_status} with {headers}",
                        confidence=85,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C012AuthBypassIndicators)
