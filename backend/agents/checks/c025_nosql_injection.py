"""C025 — NoSQL Injection Check for AihaX."""

from __future__ import annotations

import json
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


class C025NoSQLInjection(BaseCheck):
    contract = CheckContract(
        id="C025_NoSQL_Injection",
        name="NoSQL Injection",
        category=CheckCategory.INJECTION,
        description="Detects MongoDB and document store query injection vulnerabilities via operator injection (e.g. [$ne], [$gt], {\"$ne\": null}).",
        severity=Severity.CRITICAL,
        vulnerability_type="NoSQL Injection",
        cwe="CWE-943",
        owasp_category="A03:2021-Injection",
        security_property="Document database queries must validate parameter types and reject unsanitized query operator structures",
        remediation_guidance="Sanitize input object keys and cast query parameters to expected primitive types (e.g. mongo-sanitize or explicit schema types).",
        references=[
            "https://cwe.mitre.org/data/definitions/943.html",
            "https://owasp.org/www-pdf-archive/POST-NO-SQL.pdf",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "nosql_operator_payload"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            params = {"user": ["test"]}

        for param_name in list(params.keys()):
            # Test URL query operator injection: param[$ne]=random_non_existent
            test_params = dict(params)
            del test_params[param_name]
            test_params[f"{param_name}[$ne]"] = ["invalid_unmatched_value_xyz"]
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

            body = resp.response_body or ""
            # Check for MongoDB error disclosure or successful bypass condition
            if "MongoError" in body or "CastError" in body or "BSONTypeError" in body:
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=test_url,
                    affected_param=param_name,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.CRITICAL,
                    candidate_reason=f"NoSQL MongoDB exception disclosed on parameter '{param_name}' using operator payload '{param_name}[$ne]'.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"param": param_name, "error": body[:200]},
                    payload=f"{param_name}[$ne]=invalid_unmatched_value_xyz",
                    proof_response=f"MongoDB Exception in Response: {body[:250]}",
                    confidence=90,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C025NoSQLInjection)
