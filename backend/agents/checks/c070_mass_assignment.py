"""C070 — Mass Assignment / Parameter Pollution Check for AihaX."""

from __future__ import annotations

import json
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


class C070MassAssignment(BaseCheck):
    contract = CheckContract(
        id="C070_Mass_Assignment",
        name="Mass Assignment / Parameter Pollution",
        category=CheckCategory.BUSINESS_LOGIC,
        description="Detects mass assignment vulnerabilities where user registration or profile update endpoints automatically bind privileged object properties (is_admin, role, verified) into internal model state.",
        severity=Severity.HIGH,
        vulnerability_type="Mass Assignment",
        cwe="CWE-915",
        owasp_category="API3:2023-Broken Object Property Level Authorization",
        security_property="Data transfer models must explicitly declare bindable fields and ignore client-supplied privileged properties",
        remediation_guidance="Use explicit Data Transfer Objects (DTOs) with strict property schemas or field allowlists (e.g. strong parameters).",
        references=[
            "https://cwe.mitre.org/data/definitions/915.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
        ],
        verification_strategy="authorization_comparison",
        required_evidence=["affected_url", "proof_response", "bound_privileged_field"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        payload_dict = {
            "name": "Audit Test",
            "email": "audit_test@example.com",
            "is_admin": True,
            "role": "admin",
            "admin": True,
        }
        spec = RequestSpec(
            url=target_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps(payload_dict),
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp = await request_engine.execute(spec)
        if not resp.success:
            return None

        body = resp.response_body or ""
        # If response reflects the assigned admin / role property back in the serialized object
        if resp.response_status in (200, 201) and ('"is_admin":true' in body or '"is_admin": true' in body or '"role":"admin"' in body or '"role": "admin"' in body):
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=Severity.HIGH,
                candidate_reason="Target accepted and bound privileged properties ('is_admin': true, 'role': 'admin') into model state.",
                request_ids=[resp.request_id],
                evidence_ids=[resp.evidence_id],
                observed_data={"status": resp.response_status, "reflected_body": body[:200]},
                payload=json.dumps(payload_dict),
                proof_response=f"Privileged properties reflected in response model: {body[:150]}",
                confidence=90,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C070MassAssignment)
