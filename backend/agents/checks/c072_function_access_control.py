"""C072 — Function-Level Access Control Bypass Check for AihaX."""

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


class C072FunctionAccessControl(BaseCheck):
    contract = CheckContract(
        id="C072_Function_Access_Control",
        name="Function-Level Access Control Bypass",
        category=CheckCategory.BUSINESS_LOGIC,
        description="Detects Broken Function Level Authorization (BFLA) where sensitive administrative actions or HTTP methods (DELETE, PUT, POST) are exposed without checking function-level caller permissions.",
        severity=Severity.HIGH,
        vulnerability_type="Broken Access Control",
        cwe="CWE-285",
        owasp_category="API5:2023-Broken Function Level Authorization",
        security_property="Sensitive state-changing actions and HTTP methods must enforce granular function-level authorization",
        remediation_guidance="Implement explicit method and action permission checks at the controller/route level for all destructive operations.",
        references=[
            "https://cwe.mitre.org/data/definitions/285.html",
            "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
        ],
        verification_strategy="authorization_comparison",
        required_evidence=["affected_url", "proof_response", "exposed_function"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        # Test if modifying the HTTP method from GET to OPTIONS/PUT exposes administrative operations
        spec = RequestSpec(
            url=target_url,
            method="OPTIONS",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp = await request_engine.execute(spec)
        if not resp.success:
            return None

        allow_hdr = resp.response_headers.get("allow", "").upper()
        if "DELETE" in allow_hdr or "PUT" in allow_hdr:
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=Severity.HIGH,
                candidate_reason=f"Function-level method exposure: Endpoint advertises destructive methods '{allow_hdr}' without requiring administrative credentials.",
                request_ids=[resp.request_id],
                evidence_ids=[resp.evidence_id],
                observed_data={"allow_header": allow_hdr},
                payload=None,
                proof_response=f"Advertised Methods: {allow_hdr}",
                confidence=80,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C072FunctionAccessControl)
