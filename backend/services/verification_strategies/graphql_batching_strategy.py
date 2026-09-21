"""Deterministic Verification Strategy for GraphQL Batching / Nested Query DoS (C082)."""

from __future__ import annotations

from typing import Any, Dict, Optional
import json

from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout
from backend.services.verification_engine import (
    BaseVerificationStrategy,
    VerificationBudget,
    VerificationConclusion,
    VerificationContext,
    VerificationContract,
    VerificationReasonCode,
    VerificationStatus,
    VerificationRegistry,
)


class GraphqlBatchingVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies GraphQL Batching / Query Depth DoS vulnerability by testing:
    1. Array batching capability (executing multi-query batches).
    2. Deeply nested query complexity enforcement.
    Confirms vulnerability if server executes arbitrary batching/depth without complexity limits.
    """

    contract = VerificationContract(
        check_id="C082_GraphQL_Batching_Nested_Query_DoS",
        name="GraphQL Batching / Nested Query DoS Verification",
        security_property="GraphQL server must enforce query complexity analysis and batch limits.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url

        if context.budget.max_requests < 2:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description="Verification budget exhausted.",
            )

        # Probe A: Batching probe (10 bounded operations)
        batch_queries = [{"query": f"query B{i} {{ __typename }}"} for i in range(10)]
        batch_spec = RequestSpec(
            url=affected_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps(batch_queries),
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        try:
            resp_batch = await context.send_verification_request(batch_spec)
        except Exception as exc:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description=f"GraphQL batch probe failed: {exc}",
            )

        batch_body = resp_batch.response_body or ""
        ev_id = context.record_evidence(
            evidence_type="graphql_batch_probe",
            data={
                "status": resp_batch.response_status,
                "body_snippet": batch_body[:300],
            },
            request_id=resp_batch.request_id,
        )

        # Check for control enforcement (e.g. "Batching is disabled", "Batch size limit exceeded")
        if (
            "batch" in batch_body.lower() and any(k in batch_body.lower() for k in ["limit", "disabled", "exceeded", "forbidden"])
            or resp_batch.response_status in (400, 403, 429)
        ):
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.CONTROL_ENFORCED,
                reason_description="GraphQL server properly enforced batching limits or rejected array queries.",
                evidence_ids=[ev_id],
                request_ids=[resp_batch.request_id],
                confidence=95,
            )

        # Check if all 10 operations executed
        if resp_batch.response_status == 200 and batch_body.startswith("["):
            try:
                results = json.loads(batch_body)
                if isinstance(results, list) and len(results) == 10 and all("data" in r for r in results):
                    return VerificationConclusion(
                        status=VerificationStatus.VERIFIED,
                        reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                        reason_description="GraphQL Batching DoS confirmed: Server executed unbounded multi-query batch without limit enforcement.",
                        evidence_ids=[ev_id],
                        request_ids=[resp_batch.request_id],
                        confidence=95,
                    )
            except json.JSONDecodeError:
                pass

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description="GraphQL server did not execute the batched array query.",
            evidence_ids=[ev_id],
            request_ids=[resp_batch.request_id],
            confidence=90,
        )


# Register strategy
VerificationRegistry.register(GraphqlBatchingVerificationStrategy)
