"""C005 — GraphQL Introspection Check for AihaX."""

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


class C005GraphQLIntrospection(BaseCheck):
    contract = CheckContract(
        id="C005_GraphQL_Introspection",
        name="GraphQL Introspection Enabled",
        category=CheckCategory.RECON,
        description="Detects whether GraphQL schema introspection is enabled in production, exposing full schema definitions and types.",
        severity=Severity.LOW,
        vulnerability_type="Information Disclosure",
        cwe="CWE-200",
        owasp_category="A01:2021-Broken Access Control",
        security_property="GraphQL schema introspection must be disabled in production environments",
        remediation_guidance="Disable GraphQL introspection query execution in production server configuration or gateway middleware.",
        references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
        verification_strategy="graphql_introspection",
        required_evidence=["affected_url", "proof_response"],
        destructive=False,
    )

    GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql"]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        base = target_url.rstrip("/")
        query_payload = '{"query":"{ __schema { types { name } } }"}'

        for path in self.GRAPHQL_PATHS:
            gql_url = f"{base}{path}"
            spec = RequestSpec(
                url=gql_url,
                method="POST",
                headers={"Content-Type": "application/json"},
                body=query_payload,
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )

            resp_evidence = await request_engine.execute(spec)
            if not resp_evidence.success:
                continue

            # Candidate condition: 200 OK + body contains actual __schema introspection data
            body = resp_evidence.response_body or ""
            if resp_evidence.response_status == 200 and "__schema" in body and "types" in body:
                snippet = body[:400].replace("\r", " ").replace("\n", " ")
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=gql_url,
                    affected_url=gql_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=self.contract.severity,
                    candidate_reason=f"GraphQL endpoint at '{path}' executed introspection query and returned schema type metadata.",
                    request_ids=[resp_evidence.request_id],
                    evidence_ids=[resp_evidence.evidence_id],
                    observed_data={
                        "endpoint": gql_url,
                        "status_code": resp_evidence.response_status,
                        "introspection_successful": True,
                        "schema_snippet": snippet,
                    },
                    payload=query_payload,
                    proof_response=f"HTTP/1.1 200 OK\r\n\r\n{snippet}",
                    confidence=85,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C005GraphQLIntrospection)
