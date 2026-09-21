"""C082 — GraphQL Batching / Nested Query DoS Indicators Check for AihaX."""

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


class C082GraphQLBatchingNestedQueryDoS(BaseCheck):
    contract = CheckContract(
        id="C082_GraphQL_Batching_Nested_Query_DoS",
        name="GraphQL Batching / Nested Query DoS Indicators",
        category=CheckCategory.INFRASTRUCTURE,
        description="Detects GraphQL endpoints lacking query complexity analysis, depth limits, or batch query throttling.",
        severity=Severity.MEDIUM,
        vulnerability_type="GraphQL DoS Indicator",
        cwe="CWE-400",
        owasp_category="A04:2021-Insecure Design",
        security_property="GraphQL servers must enforce strict query depth limits, max aliases, and batch operation caps.",
        remediation_guidance="Implement query depth limiting (e.g. max depth 6-10), query cost analysis, and disable array-based batching if not required.",
        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"],
        verification_strategy="graphql_batching",
        required_evidence=["affected_url", "proof_request"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        # Bounded array batch probe (5 small operations)
        batch_body = json.dumps([{"query": "{ __typename }"} for _ in range(5)])
        
        spec = RequestSpec(
            url=target_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=batch_body,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        resp_evidence = await request_engine.execute(spec)
        if not resp_evidence.success:
            return None

        body = resp_evidence.response_body or ""
        # Check if server processed batch array without restriction
        if resp_evidence.response_status == 200 and body.startswith("[") and body.endswith("]"):
            try:
                data = json.loads(body)
                if isinstance(data, list) and len(data) == 5:
                    return CheckResult(
                        check_id=self.contract.id,
                        title=self.contract.name,
                        target=target_url,
                        affected_url=target_url,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=self.contract.severity,
                        candidate_reason="GraphQL endpoint executed batched array queries without batch size restriction or rejection.",
                        request_ids=[resp_evidence.request_id],
                        evidence_ids=[resp_evidence.evidence_id],
                        observed_data={"batch_size": 5, "batch_executed": True},
                        payload=batch_body,
                        proof_request=f"POST {target_url} HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{batch_body}",
                        proof_response=f"HTTP/1.1 200 OK\r\n\r\n{body[:300]}",
                        confidence=75,
                        verification_status="CANDIDATE",
                    )
            except json.JSONDecodeError:
                pass

        return None


# Register check
registry.register(C082GraphQLBatchingNestedQueryDoS)
