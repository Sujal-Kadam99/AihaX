"""C083 — GraphQL Resolver-Level Authorization Bypass Check for AihaX."""

from __future__ import annotations

from typing import Any, Dict, Optional
import json

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C083GraphQLResolverAuthBypass(BaseCheck):
    contract = CheckContract(
        id="C083_GraphQL_Resolver_Auth_Bypass",
        name="GraphQL Resolver-Level Authorization Bypass",
        category=CheckCategory.AUTH,
        description="Detects GraphQL field resolvers that fail to enforce object-level authorization when querying records by ID or tenant argument.",
        severity=Severity.HIGH,
        vulnerability_type="Broken Object Level Authorization (GraphQL)",
        cwe="CWE-285",
        owasp_category="A01:2021-Broken Access Control",
        security_property="GraphQL resolvers must enforce subject-to-object authorization checks on every individual field and nested resolver.",
        remediation_guidance="Implement authorization checks inside every individual GraphQL resolver rather than relying solely on top-level query middleware.",
        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"],
        verification_strategy="graphql_resolver_auth",
        required_evidence=["affected_url", "proof_request"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        # Bounded resolver query for testing object authorization
        resolver_query = json.dumps({"query": "query { user(id: \"1001\") { id email privateData } }"})
        
        spec = RequestSpec(
            url=target_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=resolver_query,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        resp_evidence = await request_engine.execute(spec)
        if not resp_evidence.success:
            return None

        body = resp_evidence.response_body or ""
        if resp_evidence.response_status == 200 and "data" in body and "user" in body and "errors" not in body:
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=self.contract.severity,
                candidate_reason="GraphQL resolver returned object data without field-level authorization rejection.",
                request_ids=[resp_evidence.request_id],
                evidence_ids=[resp_evidence.evidence_id],
                observed_data={"resolver": "user", "target_id": "1001"},
                payload=resolver_query,
                proof_request=f"POST {target_url} HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{resolver_query}",
                proof_response=f"HTTP/1.1 200 OK\r\n\r\n{body[:300]}",
                confidence=70,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C083GraphQLResolverAuthBypass)
