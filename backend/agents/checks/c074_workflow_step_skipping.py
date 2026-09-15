"""C074 — Step Skipping in Multi-Step Workflows Check for AihaX."""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urljoin

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C074WorkflowStepSkipping(BaseCheck):
    contract = CheckContract(
        id="C074_Workflow_Step_Skipping",
        name="Step Skipping in Multi-Step Workflows",
        category=CheckCategory.BUSINESS_LOGIC,
        description="Detects multi-step business process flaws where intermediate required stages (e.g. payment, identity verification, 2FA prompt) can be skipped by invoking final workflow endpoints directly.",
        severity=Severity.HIGH,
        vulnerability_type="Business Logic Flaw",
        cwe="CWE-840",
        owasp_category="A04:2021-Insecure Design",
        security_property="Multi-step workflows must enforce sequential state progression and validate prerequisite stages",
        remediation_guidance="Implement server-side state machines verifying that all required workflow transitions have occurred before executing completion actions.",
        references=[
            "https://cwe.mitre.org/data/definitions/840.html",
            "https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "skipped_endpoint"],
        destructive=False,
    )

    WORKFLOW_ENDPOINTS = [
        "/checkout/complete",
        "/checkout/confirmation",
        "/api/order/complete",
        "/api/verify/finalize",
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        base = target_url.rstrip("/")
        for endpoint in self.WORKFLOW_ENDPOINTS:
            flow_url = urljoin(base + "/", endpoint.lstrip("/"))
            spec = RequestSpec(
                url=flow_url,
                method="POST",
                headers={"Content-Type": "application/json"},
                body="{}",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            resp = await request_engine.execute(spec)
            if not resp.success:
                continue

            # If completion endpoint returns 200/201 success without active session prerequisite
            if resp.response_status in (200, 201) and ("success" in (resp.response_body or "").lower() or "confirmed" in (resp.response_body or "").lower()):
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=flow_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.HIGH,
                    candidate_reason=f"Workflow completion endpoint '{flow_url}' succeeded with HTTP {resp.response_status} without completing intermediate steps.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"endpoint": flow_url, "status": resp.response_status},
                    payload=None,
                    proof_response=f"Direct completion response: {(resp.response_body or '')[:150]}",
                    confidence=80,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C074WorkflowStepSkipping)
