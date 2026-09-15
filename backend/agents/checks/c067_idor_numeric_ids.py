"""C067 — Insecure Direct Object Reference (IDOR) on Numeric IDs Check for AihaX."""

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


class C067IDORNumericIDs(BaseCheck):
    contract = CheckContract(
        id="C067_IDOR_Numeric_IDs",
        name="Insecure Direct Object Reference (IDOR) on Numeric IDs",
        category=CheckCategory.BUSINESS_LOGIC,
        description="Detects Insecure Direct Object References (IDOR) where modifying incremental numeric entity identifiers (e.g. id=1001 to id=1002) exposes unauthorized user records without authorization checks.",
        severity=Severity.HIGH,
        vulnerability_type="Broken Object Level Authorization",
        cwe="CWE-639",
        owasp_category="A01:2021-Broken Access Control",
        security_property="Object identifiers must enforce object-level authorization checks ensuring callers own requested records",
        remediation_guidance="Enforce tenant and user-level ownership checks in data access layers before returning object records.",
        references=[
            "https://cwe.mitre.org/data/definitions/639.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_References_Prevention_Cheat_Sheet.html",
        ],
        verification_strategy="authorization_comparison",
        required_evidence=["affected_url", "proof_response", "target_id"],
        destructive=False,
    )

    ID_PARAM_PATTERNS = ["id", "user_id", "account_id", "order_id", "profile_id", "doc_id"]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            params = {"user_id": ["1001"]}

        for param_name, vals in list(params.items()):
            if any(k in param_name.lower() for k in self.ID_PARAM_PATTERNS):
                val = vals[0] if vals else "1001"
                if val.isdigit():
                    adjacent_id = str(int(val) + 1)
                    test_params = dict(params)
                    test_params[param_name] = [adjacent_id]
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

                    # Check if body discloses private user data indicators or structured object state
                    body = resp.response_body or ""
                    private_indicators = ["email", "address", "phone", "ssn", "balance", "credit", "billing", "token", "password_hash", "order_id", "user_id"]
                    has_private_data = any(ind in body.lower() for ind in private_indicators)

                    # If adjacent numeric ID returns 200 OK with distinct valid record data and private fields
                    if resp.response_status == 200 and len(body) > 30 and has_private_data:
                        return CheckResult(
                            check_id=self.contract.id,
                            title=self.contract.name,
                            target=target_url,
                            affected_url=test_url,
                            affected_param=param_name,
                            vulnerability_type=self.contract.vulnerability_type,
                            severity=Severity.HIGH,
                            candidate_reason=f"Adjacent numeric ID '{adjacent_id}' returned HTTP 200 OK with private object properties via parameter '{param_name}'.",
                            request_ids=[resp.request_id],
                            evidence_ids=[resp.evidence_id],
                            observed_data={"parameter": param_name, "original_id": val, "adjacent_id": adjacent_id},
                            payload=f"{param_name}={adjacent_id}",
                            proof_response=f"HTTP 200 on adjacent ID with private fields: {body[:150]}",
                            confidence=85,
                            verification_status="CANDIDATE",
                        )

        return None


# Register check
registry.register(C067IDORNumericIDs)
