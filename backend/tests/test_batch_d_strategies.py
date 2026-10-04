"""Unit tests for Batch D verification strategies (C078 to C086)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock
import pytest

from backend.services.verification_engine import (
    VerificationBudget,
    VerificationConclusion,
    VerificationContext,
    VerificationReasonCode,
    VerificationRegistry,
    VerificationStatus,
)
from backend.services.request_engine import RequestEngine, RequestEvidence
from backend.services.verification_strategies.http_request_smuggling_strategy import HttpRequestSmugglingVerificationStrategy
from backend.services.verification_strategies.web_cache_poisoning_strategy import WebCachePoisoningVerificationStrategy
from backend.services.verification_strategies.cswsh_strategy import CswshVerificationStrategy
from backend.services.verification_strategies.host_header_injection_strategy import HostHeaderInjectionVerificationStrategy
from backend.services.verification_strategies.graphql_batching_strategy import GraphqlBatchingVerificationStrategy
from backend.services.verification_strategies.graphql_resolver_auth_strategy import GraphqlResolverAuthVerificationStrategy
from backend.services.verification_strategies.oauth_redirect_uri_strategy import OAuthRedirectUriVerificationStrategy
from backend.services.verification_strategies.oauth_state_parameter_strategy import OAuthStateParameterVerificationStrategy
from backend.services.verification_strategies.insecure_deserialization_strategy import InsecureDeserializationVerificationStrategy


def make_evidence(request_id: str, response_status: int, response_body: str, response_headers: dict | None = None, success: bool = True) -> RequestEvidence:
    return RequestEvidence(
        request_id=request_id,
        timestamp="2026-09-17T00:00:00Z",
        method="GET",
        url="http://target.test",
        request_headers={},
        request_body=None,
        response_status=response_status,
        response_headers=response_headers or {},
        response_body=response_body,
        response_size=len(response_body),
        duration_ms=10.0,
        truncated=False,
        redirect_chain=[],
        scope_decision={"allowed": True},
        transport_error=None,
        request_hash="hash",
        response_hash="hash",
        success=success,
    )


@pytest.fixture
def mock_request_engine():
    engine = AsyncMock(spec=RequestEngine)
    engine.execute = AsyncMock()
    return engine


@pytest.fixture
def default_budget():
    return VerificationBudget(max_requests=10, max_duration_seconds=30.0)


# ==============================================================================
# 1. C078 — HTTP Request Smuggling
# ==============================================================================

@pytest.mark.asyncio
async def test_c078_http_request_smuggling_verified(mock_request_engine, default_budget):
    ctx = VerificationContext(
        finding_id="F078",
        target_url="http://target.test/api",
        candidate_evidence={"affected_url": "http://target.test/api"},
        request_engine=mock_request_engine,
        check_id="C078_HTTP_Request_Smuggling",
        budget=default_budget,
    )
    # Probe 1 accepted (200), Follow-up probe 2 gets 404 on smuggled canary path
    resp1 = make_evidence("R1", 200, "OK")
    resp2 = make_evidence("R2", 404, "Not Found /aihax_smuggle_canary")
    mock_request_engine.execute.side_effect = [resp1, resp2]

    strategy = HttpRequestSmugglingVerificationStrategy()
    conclusion = await strategy.verify(ctx)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.PROPERTY_DEMONSTRATED
    assert conclusion.confidence >= 85


@pytest.mark.asyncio
async def test_c078_http_request_smuggling_false_positive_when_rejected(mock_request_engine, default_budget):
    ctx = VerificationContext(
        finding_id="F078",
        target_url="http://target.test/api",
        candidate_evidence={"affected_url": "http://target.test/api"},
        request_engine=mock_request_engine,
        check_id="C078_HTTP_Request_Smuggling",
        budget=default_budget,
    )
    # Server cleanly rejects ambiguous dual framing with 400 Bad Request
    resp1 = make_evidence("R1", 400, "Bad Request: Dual Transfer-Encoding and Content-Length not allowed")
    mock_request_engine.execute.return_value = resp1

    strategy = HttpRequestSmugglingVerificationStrategy()
    conclusion = await strategy.verify(ctx)

    assert conclusion.status == VerificationStatus.FALSE_POSITIVE
    assert conclusion.reason_code == VerificationReasonCode.CONTROL_ENFORCED


# ==============================================================================
# 2. C079 — Web Cache Poisoning
# ==============================================================================

@pytest.mark.asyncio
async def test_c079_web_cache_poisoning_verified(mock_request_engine, default_budget):
    ctx = VerificationContext(
        finding_id="F079",
        target_url="http://target.test/static/app.js",
        candidate_evidence={"affected_url": "http://target.test/static/app.js"},
        request_engine=mock_request_engine,
        check_id="C079_Web_Cache_Poisoning",
        budget=default_budget,
    )
    # Both responses contain the poisoned canary host (served from cache to clean request)
    resp1 = make_evidence("R1", 200, "import 'https://aihax-poison-canary.test/x.js';", {"x-cache": "MISS"})
    # Mock return so resp2 contains the exact canary host that was passed in resp1
    def side_effect(spec):
        canary = spec.headers.get("X-Forwarded-Host", "aihax-poison-canary.test")
        # For clean request (no X-Forwarded-Host), simulate cached poisoned body from earlier
        body = f"import 'https://{mock_request_engine._saved_canary}/x.js';"
        return make_evidence("R", 200, body, {"x-cache": "HIT"})

    async def execute_mock(spec):
        if "X-Forwarded-Host" in spec.headers:
            mock_request_engine._saved_canary = spec.headers["X-Forwarded-Host"]
            return make_evidence("R1", 200, f"import 'https://{mock_request_engine._saved_canary}/x.js';", {"x-cache": "MISS"})
        else:
            return make_evidence("R2", 200, f"import 'https://{mock_request_engine._saved_canary}/x.js';", {"x-cache": "HIT"})

    mock_request_engine.execute.side_effect = execute_mock

    strategy = WebCachePoisoningVerificationStrategy()
    conclusion = await strategy.verify(ctx)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.PROPERTY_DEMONSTRATED
    assert conclusion.confidence == 100


@pytest.mark.asyncio
async def test_c079_web_cache_poisoning_false_positive_when_not_cached(mock_request_engine, default_budget):
    ctx = VerificationContext(
        finding_id="F079",
        target_url="http://target.test/home",
        candidate_evidence={"affected_url": "http://target.test/home"},
        request_engine=mock_request_engine,
        check_id="C079_Web_Cache_Poisoning",
        budget=default_budget,
    )
    # Clean victim request receives normal unpoisoned response
    async def execute_mock(spec):
        if "X-Forwarded-Host" in spec.headers:
            canary = spec.headers["X-Forwarded-Host"]
            return make_evidence("R1", 200, f"Host was {canary}")
        else:
            return make_evidence("R2", 200, "Clean unpoisoned page content")

    mock_request_engine.execute.side_effect = execute_mock

    strategy = WebCachePoisoningVerificationStrategy()
    conclusion = await strategy.verify(ctx)

    assert conclusion.status == VerificationStatus.FALSE_POSITIVE
    assert conclusion.reason_code == VerificationReasonCode.CONTRADICTORY_EVIDENCE


# ==============================================================================
# 3. C080 — Cross-Site WebSocket Hijacking (CSWSH)
# ==============================================================================

@pytest.mark.asyncio
async def test_c080_cswsh_verified(mock_request_engine, default_budget):
    ctx = VerificationContext(
        finding_id="F080",
        target_url="http://target.test/ws",
        candidate_evidence={"affected_url": "http://target.test/ws"},
        request_engine=mock_request_engine,
        check_id="C080_Cross_Site_WebSocket_Hijacking",
        budget=default_budget,
    )
    # Server accepts WebSocket handshake from untrusted Origin with 101 Switching Protocols
    resp = make_evidence("R1", 101, "", {"upgrade": "websocket", "connection": "Upgrade", "sec-websocket-accept": "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="})
    mock_request_engine.execute.return_value = resp

    strategy = CswshVerificationStrategy()
    conclusion = await strategy.verify(ctx)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.PROPERTY_DEMONSTRATED
    assert conclusion.confidence == 95


@pytest.mark.asyncio
async def test_c080_cswsh_false_positive_when_origin_validated(mock_request_engine, default_budget):
    ctx = VerificationContext(
        finding_id="F080",
        target_url="http://target.test/ws",
        candidate_evidence={"affected_url": "http://target.test/ws"},
        request_engine=mock_request_engine,
        check_id="C080_Cross_Site_WebSocket_Hijacking",
        budget=default_budget,
    )
    # Server rejects unauthorized Origin with 403 Forbidden
    resp = make_evidence("R1", 403, "Forbidden: Cross-origin WebSocket connections not permitted")
    mock_request_engine.execute.return_value = resp

    strategy = CswshVerificationStrategy()
    conclusion = await strategy.verify(ctx)

    assert conclusion.status == VerificationStatus.FALSE_POSITIVE
    assert conclusion.reason_code == VerificationReasonCode.CONTROL_ENFORCED


# ==============================================================================
# 4. C081 — Host Header Injection
# ==============================================================================

@pytest.mark.asyncio
async def test_c081_host_header_injection_verified(mock_request_engine, default_budget):
    ctx = VerificationContext(
        finding_id="F081",
        target_url="http://target.test/password-reset",
        candidate_evidence={"affected_url": "http://target.test/password-reset"},
        request_engine=mock_request_engine,
        check_id="C081_Host_Header_Injection",
        budget=default_budget,
    )
    # Injected host is reflected into action link
    async def execute_mock(spec):
        injected = spec.headers.get("Host", "target.test")
        body = f'<html><body><a href="http://{injected}/reset?token=xyz">Click here to reset</a></body></html>'
        return make_evidence("R1", 200, body)

    mock_request_engine.execute.side_effect = execute_mock

    strategy = HostHeaderInjectionVerificationStrategy()
    conclusion = await strategy.verify(ctx)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.PROPERTY_DEMONSTRATED


@pytest.mark.asyncio
async def test_c081_host_header_injection_false_positive_when_rejected(mock_request_engine, default_budget):
    ctx = VerificationContext(
        finding_id="F081",
        target_url="http://target.test/login",
        candidate_evidence={"affected_url": "http://target.test/login"},
        request_engine=mock_request_engine,
        check_id="C081_Host_Header_Injection",
        budget=default_budget,
    )
    resp = make_evidence("R1", 400, "Invalid Host header")
    mock_request_engine.execute.return_value = resp

    strategy = HostHeaderInjectionVerificationStrategy()
    conclusion = await strategy.verify(ctx)

    assert conclusion.status == VerificationStatus.FALSE_POSITIVE
    assert conclusion.reason_code == VerificationReasonCode.CONTROL_ENFORCED


# ==============================================================================
# 5. C082 — GraphQL Batching / Nested Query DoS
# ==============================================================================

@pytest.mark.asyncio
async def test_c082_graphql_batching_verified(mock_request_engine, default_budget):
    ctx = VerificationContext(
        finding_id="F082",
        target_url="http://target.test/graphql",
        candidate_evidence={"affected_url": "http://target.test/graphql"},
        request_engine=mock_request_engine,
        check_id="C082_GraphQL_Batching_Nested_Query_DoS",
        budget=default_budget,
    )
    # Server executes all 10 batched queries
    batch_resp = json.dumps([{"data": {"__typename": "Query"}} for _ in range(10)])
    resp = make_evidence("R1", 200, batch_resp)
    mock_request_engine.execute.return_value = resp

    strategy = GraphqlBatchingVerificationStrategy()
    conclusion = await strategy.verify(ctx)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.PROPERTY_DEMONSTRATED


@pytest.mark.asyncio
async def test_c082_graphql_batching_false_positive_when_limited(mock_request_engine, default_budget):
    ctx = VerificationContext(
        finding_id="F082",
        target_url="http://target.test/graphql",
        candidate_evidence={"affected_url": "http://target.test/graphql"},
        request_engine=mock_request_engine,
        check_id="C082_GraphQL_Batching_Nested_Query_DoS",
        budget=default_budget,
    )
    # Server blocks array batching
    resp = make_evidence("R1", 400, '{"errors": [{"message": "Batch query execution is disabled."}]}')
    mock_request_engine.execute.return_value = resp

    strategy = GraphqlBatchingVerificationStrategy()
    conclusion = await strategy.verify(ctx)

    assert conclusion.status == VerificationStatus.FALSE_POSITIVE
    assert conclusion.reason_code == VerificationReasonCode.CONTROL_ENFORCED


# ==============================================================================
# 6. C083 — GraphQL Resolver Authorization Bypass
# ==============================================================================

@pytest.mark.asyncio
async def test_c083_graphql_resolver_auth_verified(mock_request_engine, default_budget):
    ctx = VerificationContext(
        finding_id="F083",
        target_url="http://target.test/graphql",
        candidate_evidence={"affected_url": "http://target.test/graphql"},
        request_engine=mock_request_engine,
        check_id="C083_GraphQL_Resolver_Auth_Bypass",
        budget=default_budget,
    )
    # Server returns private user data across accounts
    resp_body = '{"data": {"user": {"id": "1001", "email": "victim@test.com", "privateData": "secret-123"}}}'
    resp = make_evidence("R1", 200, resp_body)
    mock_request_engine.execute.return_value = resp

    strategy = GraphqlResolverAuthVerificationStrategy()
    conclusion = await strategy.verify(ctx)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.PROPERTY_DEMONSTRATED


@pytest.mark.asyncio
async def test_c083_graphql_resolver_auth_false_positive_when_enforced(mock_request_engine, default_budget):
    ctx = VerificationContext(
        finding_id="F083",
        target_url="http://target.test/graphql",
        candidate_evidence={"affected_url": "http://target.test/graphql"},
        request_engine=mock_request_engine,
        check_id="C083_GraphQL_Resolver_Auth_Bypass",
        budget=default_budget,
    )
    # Resolver returns unauthorized error
    resp_body = '{"data": {"user": null}, "errors": [{"message": "Unauthorized access to object"}]}'
    resp = make_evidence("R1", 200, resp_body)
    mock_request_engine.execute.return_value = resp

    strategy = GraphqlResolverAuthVerificationStrategy()
    conclusion = await strategy.verify(ctx)

    assert conclusion.status == VerificationStatus.FALSE_POSITIVE
    assert conclusion.reason_code == VerificationReasonCode.AUTH_REQUIRED_OR_ENFORCED


# ==============================================================================
# 7. C084 — OAuth Redirect URI Validation Weakness
# ==============================================================================

@pytest.mark.asyncio
async def test_c084_oauth_redirect_uri_verified(mock_request_engine, default_budget):
    ctx = VerificationContext(
        finding_id="F084",
        target_url="http://target.test/oauth/authorize?client_id=123",
        candidate_evidence={"affected_url": "http://target.test/oauth/authorize?client_id=123"},
        request_engine=mock_request_engine,
        check_id="C084_OAuth_Redirect_URI_Validation",
        budget=default_budget,
    )
    # Server redirects to untrusted canary callback
    resp = make_evidence("R1", 302, "", {"location": "https://aihax-oauth-canary.test/callback?code=AUTH_CODE_123"})
    mock_request_engine.execute.return_value = resp

    strategy = OAuthRedirectUriVerificationStrategy()
    conclusion = await strategy.verify(ctx)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.PROPERTY_DEMONSTRATED
    assert conclusion.confidence == 100


@pytest.mark.asyncio
async def test_c084_oauth_redirect_uri_false_positive_when_rejected(mock_request_engine, default_budget):
    ctx = VerificationContext(
        finding_id="F084",
        target_url="http://target.test/oauth/authorize?client_id=123",
        candidate_evidence={"affected_url": "http://target.test/oauth/authorize?client_id=123"},
        request_engine=mock_request_engine,
        check_id="C084_OAuth_Redirect_URI_Validation",
        budget=default_budget,
    )
    # Server rejects invalid redirect_uri
    resp = make_evidence("R1", 400, "Error: invalid_redirect_uri parameter does not match whitelist")
    mock_request_engine.execute.return_value = resp

    strategy = OAuthRedirectUriVerificationStrategy()
    conclusion = await strategy.verify(ctx)

    assert conclusion.status == VerificationStatus.FALSE_POSITIVE
    assert conclusion.reason_code == VerificationReasonCode.CONTROL_ENFORCED


# ==============================================================================
# 8. C085 — Missing OAuth state Parameter
# ==============================================================================

@pytest.mark.asyncio
async def test_c085_missing_oauth_state_verified(mock_request_engine, default_budget):
    ctx = VerificationContext(
        finding_id="F085",
        target_url="http://target.test/oauth/authorize?client_id=123&redirect_uri=https://app.test/cb",
        candidate_evidence={"affected_url": "http://target.test/oauth/authorize?client_id=123&redirect_uri=https://app.test/cb"},
        request_engine=mock_request_engine,
        check_id="C085_Missing_OAuth_State_Parameter",
        budget=default_budget,
    )
    # Server completes flow without state
    resp = make_evidence("R1", 302, "", {"location": "https://app.test/cb?code=AUTH_CODE_123"})
    mock_request_engine.execute.return_value = resp

    strategy = OAuthStateParameterVerificationStrategy()
    conclusion = await strategy.verify(ctx)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.PROPERTY_DEMONSTRATED


@pytest.mark.asyncio
async def test_c085_missing_oauth_state_false_positive_when_state_required(mock_request_engine, default_budget):
    ctx = VerificationContext(
        finding_id="F085",
        target_url="http://target.test/oauth/authorize?client_id=123&redirect_uri=https://app.test/cb",
        candidate_evidence={"affected_url": "http://target.test/oauth/authorize?client_id=123&redirect_uri=https://app.test/cb"},
        request_engine=mock_request_engine,
        check_id="C085_Missing_OAuth_State_Parameter",
        budget=default_budget,
    )
    # Server mandates state
    resp = make_evidence("R1", 400, "Missing required parameter: state")
    mock_request_engine.execute.return_value = resp

    strategy = OAuthStateParameterVerificationStrategy()
    conclusion = await strategy.verify(ctx)

    assert conclusion.status == VerificationStatus.FALSE_POSITIVE
    assert conclusion.reason_code == VerificationReasonCode.CONTROL_ENFORCED


# ==============================================================================
# 9. C086 — Insecure Deserialization
# ==============================================================================

@pytest.mark.asyncio
async def test_c086_insecure_deserialization_verified(mock_request_engine, default_budget):
    ctx = VerificationContext(
        finding_id="F086",
        target_url="http://target.test/api/import",
        candidate_evidence={"affected_url": "http://target.test/api/import"},
        request_engine=mock_request_engine,
        check_id="C086_Insecure_Deserialization_Indicators",
        budget=default_budget,
    )
    # Server deserializes object and triggers unpickling / unserialize exception indicator
    resp = make_evidence("R1", 500, "Error during object instantiation: unserialize() failed on class stdClass")
    mock_request_engine.execute.return_value = resp

    strategy = InsecureDeserializationVerificationStrategy()
    conclusion = await strategy.verify(ctx)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.PROPERTY_DEMONSTRATED


@pytest.mark.asyncio
async def test_c086_insecure_deserialization_false_positive_when_rejected(mock_request_engine, default_budget):
    ctx = VerificationContext(
        finding_id="F086",
        target_url="http://target.test/api/import",
        candidate_evidence={"affected_url": "http://target.test/api/import"},
        request_engine=mock_request_engine,
        check_id="C086_Insecure_Deserialization_Indicators",
        budget=default_budget,
    )
    # Server rejects unsupported media type
    resp = make_evidence("R1", 415, "Unsupported Media Type")
    mock_request_engine.execute.return_value = resp

    strategy = InsecureDeserializationVerificationStrategy()
    conclusion = await strategy.verify(ctx)

    assert conclusion.status == VerificationStatus.FALSE_POSITIVE
    assert conclusion.reason_code == VerificationReasonCode.CONTROL_ENFORCED


# ==============================================================================
# 10. Registry Resolution Test for All 9 Batch D Checks
# ==============================================================================

def test_all_9_batch_d_checks_resolve_to_dedicated_strategies():
    batch_d_ids = [
        "C078_HTTP_Request_Smuggling",
        "C079_Web_Cache_Poisoning",
        "C080_Cross_Site_WebSocket_Hijacking",
        "C081_Host_Header_Injection",
        "C082_GraphQL_Batching_Nested_Query_DoS",
        "C083_GraphQL_Resolver_Auth_Bypass",
        "C084_OAuth_Redirect_URI_Validation",
        "C085_Missing_OAuth_State_Parameter",
        "C086_Insecure_Deserialization_Indicators",
    ]

    for cid in batch_d_ids:
        strat = VerificationRegistry.get_strategy(cid)
        assert strat is not None, f"Strategy missing for {cid}"
        assert not strat.__class__.__name__.startswith("Generic"), f"Expected dedicated strategy for {cid}, got {strat.__class__.__name__}"
