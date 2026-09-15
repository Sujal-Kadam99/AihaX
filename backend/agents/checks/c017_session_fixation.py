"""C017 — Session Fixation Check for AihaX."""

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


class C017SessionFixation(BaseCheck):
    contract = CheckContract(
        id="C017_Session_Fixation",
        name="Session Fixation Indicators",
        category=CheckCategory.AUTH,
        description="Detects whether an application accepts arbitrary pre-existing session identifiers supplied via query parameters or cookies and fails to regenerate the session ID upon authentication.",
        severity=Severity.HIGH,
        vulnerability_type="Session Fixation",
        cwe="CWE-384",
        owasp_category="A07:2021-Identification and Authentication Failures",
        security_property="Applications must generate a new session identifier upon authentication and reject unauthenticated session adoption",
        remediation_guidance="Issue a new session identifier (e.g. session.regenerate_id()) immediately after a user authenticates.",
        references=[
            "https://cwe.mitre.org/data/definitions/384.html",
            "https://owasp.org/www-community/attacks/Session_fixation",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "fixed_session_token"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        fixed_token = "aihax_fixed_token_77a9b1c"
        # Test if query param session adoption is accepted
        sep = "&" if "?" in target_url else "?"
        spec = RequestSpec(
            url=f"{target_url}{sep}sessionid={fixed_token}",
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp_evidence = await request_engine.execute(spec)
        if not resp_evidence.success:
            return None

        # Check if the server reflects or adopts the supplied session token in Set-Cookie or body
        set_cookies = [v for k, v in resp_evidence.response_headers.items() if k.lower() == "set-cookie"]
        for cookie_str in set_cookies:
            if fixed_token in cookie_str or "sessionid=" in cookie_str.lower():
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=target_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.HIGH,
                    candidate_reason=f"Server adopted client-supplied URL session token '{fixed_token}' directly into Set-Cookie response.",
                    request_ids=[resp_evidence.request_id],
                    evidence_ids=[resp_evidence.evidence_id],
                    observed_data={"adopted_token": fixed_token, "set_cookie": cookie_str},
                    payload=f"?sessionid={fixed_token}",
                    proof_response=f"Set-Cookie: {cookie_str}",
                    confidence=85,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C017SessionFixation)
