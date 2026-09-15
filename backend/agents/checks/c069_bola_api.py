"""C069 — Broken Object Level Authorization (BOLA) in API Endpoints Check for AihaX."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional
from urllib.parse import urlparse, urlunparse

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C069BOLAAPI(BaseCheck):
    contract = CheckContract(
        id="C069_BOLA_API",
        name="Broken Object Level Authorization (BOLA) in API Endpoints",
        category=CheckCategory.BUSINESS_LOGIC,
        description="Detects Broken Object Level Authorization (BOLA / IDOR) in REST API path parameters (/api/users/{id}, /api/orders/{id}) where manipulating path-based entity IDs returns unauthorized resource objects.",
        severity=Severity.HIGH,
        vulnerability_type="Broken Object Level Authorization",
        cwe="CWE-639",
        owasp_category="API1:2023-Broken Object Level Authorization",
        security_property="API endpoints with path-based resource IDs must enforce subject-to-resource ownership authorization",
        remediation_guidance="Implement fine-grained object-level authorization policies checking that the authenticated caller has permission to access the specific entity ID.",
        references=[
            "https://cwe.mitre.org/data/definitions/639.html",
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        ],
        verification_strategy="authorization_comparison",
        required_evidence=["affected_url", "proof_response", "tampered_path_id"],
        destructive=False,
    )

    API_PATH_PATTERN = re.compile(r"/(users|orders|accounts|invoices|profiles|documents)/(\d+)", re.I)

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        parsed = urlparse(target_url)
        match = self.API_PATH_PATTERN.search(parsed.path)
        if not match:
            return None

        resource_type, current_id = match.group(1), match.group(2)
        tampered_id = str(int(current_id) + 1)
        new_path = parsed.path[: match.start(2)] + tampered_id + parsed.path[match.end(2) :]
        test_url = urlunparse((parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, parsed.fragment))

        spec = RequestSpec(
            url=test_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp = await request_engine.execute(spec)
        if not resp.success:
            return None

        # If tampered ID returns 200 OK with valid JSON or record data
        if resp.response_status == 200 and len(resp.response_body or "") > 30:
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=test_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=Severity.HIGH,
                candidate_reason=f"BOLA flaw detected in REST API endpoint: Accessing '{resource_type}/{tampered_id}' returned HTTP 200 OK without authorization enforcement.",
                request_ids=[resp.request_id],
                evidence_ids=[resp.evidence_id],
                observed_data={"resource_type": resource_type, "original_id": current_id, "tampered_id": tampered_id},
                payload=f"Path ID: {tampered_id}",
                proof_response=f"HTTP 200 on tampered API resource: {(resp.response_body or '')[:150]}",
                confidence=85,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C069BOLAAPI)
