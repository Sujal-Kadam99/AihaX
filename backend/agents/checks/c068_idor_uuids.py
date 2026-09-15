"""C068 — Insecure Direct Object Reference (IDOR) on UUIDs Check for AihaX."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C068IDORUUIDs(BaseCheck):
    contract = CheckContract(
        id="C068_IDOR_UUIDs",
        name="Insecure Direct Object Reference (IDOR) on UUIDs",
        category=CheckCategory.BUSINESS_LOGIC,
        description="Detects Broken Object Level Authorization on GUID/UUID identifiers where knowing or guessing a resource UUID permits unauthorized read/write access without caller authorization.",
        severity=Severity.HIGH,
        vulnerability_type="Broken Object Level Authorization",
        cwe="CWE-639",
        owasp_category="A01:2021-Broken Access Control",
        security_property="UUID parameters must still enforce object-level ownership checks and not rely solely on UUID unguessability",
        remediation_guidance="Implement explicit ownership and authorization checks in backend controllers rather than relying on UUID complexity as a security boundary.",
        references=[
            "https://cwe.mitre.org/data/definitions/639.html",
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        ],
        verification_strategy="authorization_comparison",
        required_evidence=["affected_url", "proof_response", "target_uuid"],
        destructive=False,
    )

    UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name, vals in list(params.items()):
            val = vals[0] if vals else ""
            if self.UUID_REGEX.match(val):
                test_uuid = "00000000-0000-0000-0000-000000000000"
                test_params = dict(params)
                test_params[param_name] = [test_uuid]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                spec = RequestSpec(
                    url=test_url,
                    method="GET",
                    timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
                )
                resp = await request_engine.execute(spec)
                if not resp.success:
                    continue

                if resp.response_status in (200, 204):
                    return CheckResult(
                        check_id=self.contract.id,
                        title=self.contract.name,
                        target=target_url,
                        affected_url=test_url,
                        affected_param=param_name,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.HIGH,
                        candidate_reason=f"Endpoint accepted arbitrary UUID '{test_uuid}' without authorization challenge (HTTP {resp.response_status}).",
                        request_ids=[resp.request_id],
                        evidence_ids=[resp.evidence_id],
                        observed_data={"parameter": param_name, "test_uuid": test_uuid, "status": resp.response_status},
                        payload=f"{param_name}={test_uuid}",
                        proof_response=f"Arbitrary UUID Accepted with status: {resp.response_status}",
                        confidence=80,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C068IDORUUIDs)
