"""Deterministic Verification Strategy for GraphQL Resolver Authorization Bypass (C083)."""

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


class GraphqlResolverAuthVerificationStrategy(BaseVerificationStrategy):
    """
    Verifies GraphQL Resolver-Level Authorization Bypass (BOLA / IDOR) by testing whether
    an unprivileged or foreign identity's session can query an unauthorized object resolver.
    """

    contract = VerificationContract(
        check_id="C083_GraphQL_Resolver_Auth_Bypass",
        name="GraphQL Resolver Authorization Bypass Verification",
        security_property="GraphQL field resolvers must enforce subject-level access control on target objects.",
        required_evidence_fields=["affected_url"],
        destructive=False,
    )

    async def verify(self, context: VerificationContext) -> VerificationConclusion:
        candidate = context.candidate_evidence
        affected_url = candidate.get("affected_url") or context.target_url

        if context.budget.max_requests <= 0:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.BUDGET_EXHAUSTED,
                reason_description="Verification budget exhausted.",
            )

        query_body = candidate.get("payload") or json.dumps({
            "query": "query { user(id: \"1001\") { id email privateData } }"
        })

        spec = RequestSpec(
            url=affected_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=query_body,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        try:
            resp = await context.send_verification_request(spec)
        except Exception as exc:
            return VerificationConclusion(
                status=VerificationStatus.INCONCLUSIVE,
                reason_code=VerificationReasonCode.ENDPOINT_UNAVAILABLE,
                reason_description=f"GraphQL resolver query failed: {exc}",
            )

        status = resp.response_status
        body = resp.response_body or ""

        ev_id = context.record_evidence(
            evidence_type="graphql_resolver_auth_check",
            data={"status": status, "body": body[:300]},
            request_id=resp.request_id,
        )

        # Check for authorization error / resolver rejection
        if (
            "unauthorized" in body.lower()
            or "forbidden" in body.lower()
            or "access denied" in body.lower()
            or '"errors":' in body
            or status in (401, 403)
        ):
            return VerificationConclusion(
                status=VerificationStatus.FALSE_POSITIVE,
                reason_code=VerificationReasonCode.AUTH_REQUIRED_OR_ENFORCED,
                reason_description="GraphQL resolver properly enforced authorization and rejected cross-account access.",
                evidence_ids=[ev_id],
                request_ids=[resp.request_id],
                confidence=95,
            )

        # Successful unauthorized retrieval of private data
        if status == 200 and '"data":' in body and ('"email":' in body or '"privateData":' in body or '"user":' in body):
            return VerificationConclusion(
                status=VerificationStatus.VERIFIED,
                reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED,
                reason_description="GraphQL Resolver Authorization Bypass confirmed: Private object data retrieved without resolver-level access control.",
                evidence_ids=[ev_id],
                request_ids=[resp.request_id],
                confidence=95,
            )

        return VerificationConclusion(
            status=VerificationStatus.FALSE_POSITIVE,
            reason_code=VerificationReasonCode.CONTRADICTORY_EVIDENCE,
            reason_description="GraphQL query did not retrieve unauthorized object data.",
            evidence_ids=[ev_id],
            request_ids=[resp.request_id],
            confidence=90,
        )


# Register strategy
VerificationRegistry.register(GraphqlResolverAuthVerificationStrategy)
