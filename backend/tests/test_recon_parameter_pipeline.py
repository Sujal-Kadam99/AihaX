from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from backend.agents.checks.c023_sql_injection import C023SQLInjection
from backend.core.scope_validator import ScopeValidator
from backend.recon.endpoint_discovery import EndpointDiscoveryEngine
from backend.recon.models import DiscoveredAsset, DiscoverySource
from backend.services.request_engine import MockTransport, RawResponse, RequestEngine
from backend.services.campaign_executor import CampaignRequestBudget
from backend.services.verification_engine import (
    VerificationContext,
    VerificationStatus,
)
from backend.services.verification_strategies.sql_injection_strategy import (
    SqlInjectionVerificationStrategy,
)


@pytest.mark.asyncio
async def test_recon_has_separate_bound_without_weakening_check_budget():
    budget = CampaignRequestBudget(
        campaign_budget=10,
        target_budget=10,
        check_budget=1,
        recon_budget=3,
    )

    assert (await budget.reserve_request("http://127.0.0.1:8764", "RECON_DISCOVERY"))[0]
    assert (await budget.reserve_request("http://127.0.0.1:8764", "RECON_DISCOVERY"))[0]
    assert (await budget.reserve_request("http://127.0.0.1:8764", "RECON_DISCOVERY"))[0]
    assert not (await budget.reserve_request("http://127.0.0.1:8764", "RECON_DISCOVERY"))[0]
    assert (await budget.reserve_request("http://127.0.0.1:8764", "C023_SQL_Injection"))[0]
    assert not (await budget.reserve_request("http://127.0.0.1:8764", "C023_SQL_Injection"))[0]


@pytest.mark.asyncio
async def test_javascript_route_discovery_keeps_query_parameter_provenance():
    base_url = "http://127.0.0.1:8765"
    script_url = f"{base_url}/main.js"
    transport = MockTransport(default_body="")
    transport.register_response(
        url=script_url,
        body='const endpoint = `/rest/products/search?q=${searchTerm}`;',
        headers={"content-type": "application/javascript"},
    )
    scope = ScopeValidator(in_scope_assets=[base_url])
    engine = RequestEngine(scope_validator=scope, transport=transport)
    discovery = EndpointDiscoveryEngine(engine, scope)
    asset = DiscoveredAsset(
        asset_id="asset-local",
        raw_asset=base_url,
        canonical_url=base_url,
        hostname="127.0.0.1",
        scheme="http",
        port=8765,
        path="/",
        asset_type="WEB_APPLICATION",
        source=DiscoverySource.USER_INPUT,
        scope_status="IN_SCOPE",
    )
    discovered = []

    await discovery._analyze_javascript_file(
        script_url,
        base_url,
        lambda url, **kwargs: discovery_endpoint_sink(discovered, url, **kwargs),
    )

    endpoint = next(item for item in discovered if item.path == "/rest/products/search")
    assert endpoint.url == f"{base_url}/rest/products/search"
    assert endpoint.parameters == ["q"]
    assert endpoint.source == DiscoverySource.JS_ANALYSIS


def discovery_endpoint_sink(discovered, url, **kwargs):
    """Mirror the discovery engine's endpoint admission callback for this unit test."""
    from backend.recon.models import AuthRequirement, DiscoveredEndpoint, EndpointType

    parsed = urlparse(url)
    discovered.append(DiscoveredEndpoint(
        endpoint_id="endpoint-test",
        url=url,
        path=parsed.path,
        method=kwargs.get("method", "GET"),
        endpoint_type=kwargs.get("ep_type", EndpointType.PAGE),
        source=kwargs.get("source", DiscoverySource.HTML_CRAWL),
        parameters=kwargs.get("params", []),
        auth_required=kwargs.get("auth_req", AuthRequirement.UNKNOWN),
        is_api=kwargs.get("is_api", False),
        is_graphql=kwargs.get("is_graphql", False),
    ))


@pytest.mark.asyncio
async def test_sql_injection_check_tests_discovered_parameter_and_captures_reproduction():
    base_url = "http://127.0.0.1:8766"
    search_url = f"{base_url}/rest/products/search"

    def respond(method, url, headers, params, body):
        query = parse_qs(urlparse(url).query)
        value = query.get("q", [""])[0]
        if value == "' OR 1=1--":
            return RawResponse(
                status_code=500,
                headers={"content-type": "text/html"},
                body=b"<title>Error: SQLITE_ERROR: incomplete input</title>",
                observed_size=54,
            )
        return RawResponse(
            status_code=200,
            headers={"content-type": "application/json"},
            body=b'{"status":"success","data":[]}',
            observed_size=32,
        )

    transport = MockTransport(default_body=b"not found")
    transport.register_handler(lambda method, url: url.startswith(search_url), respond)
    scope = ScopeValidator(in_scope_assets=[base_url])
    engine = RequestEngine(scope_validator=scope, transport=transport)
    check = C023SQLInjection()

    result = await check.execute(
        engine,
        base_url,
        {
            "discovered_endpoints": [{
                "url": f"{base_url}/v3/ip-country",
                "method": "GET",
                "parameters": ["key", "format", "callback"],
                "source": "JS_ANALYSIS",
            }, {
                "url": search_url,
                "method": "GET",
                "parameters": ["q"],
                "source": "JS_ANALYSIS",
            }],
        },
    )

    assert result is not None
    assert result.affected_param == "q"
    assert result.payload == "' OR 1=1--"
    assert result.proof_request.startswith("GET /rest/products/search?q=%27+OR+1%3D1-- HTTP/1.1")
    assert result.evidence_ids and result.request_ids
    assert "/rest/products/search?q=1" in transport.calls[0]["url"]
    assert len(transport.calls) <= check.contract.max_requests


@pytest.mark.asyncio
async def test_sql_injection_verifier_replays_exact_payload_against_benign_baseline():
    base_url = "http://127.0.0.1:8767"
    search_url = f"{base_url}/rest/products/search"

    def respond(method, url, headers, params, body):
        value = parse_qs(urlparse(url).query).get("q", [""])[0]
        if value == "' OR 1=1--":
            return RawResponse(
                status_code=500,
                headers={"content-type": "text/html"},
                body=b"<title>Error: SQLITE_ERROR: incomplete input</title>",
                observed_size=54,
            )
        return RawResponse(
            status_code=200,
            headers={"content-type": "application/json"},
            body=b'{"status":"success","data":[]}',
            observed_size=32,
        )

    transport = MockTransport(default_body=b"not found")
    transport.register_handler(lambda method, url: url.startswith(search_url), respond)
    engine = RequestEngine(scope_validator=ScopeValidator(in_scope_assets=[base_url]), transport=transport)
    candidate = {
        "affected_url": f"{search_url}?q=%27+OR+1%3D1--",
        "affected_param": "q",
        "payload": "' OR 1=1--",
        "proof_request": "GET /rest/products/search?q=%27+OR+1%3D1-- HTTP/1.1\r\nHost: 127.0.0.1:8767\r\n\r\n",
    }
    context = VerificationContext(
        finding_id="finding-test",
        check_id="C023_SQL_Injection",
        target_url=base_url,
        candidate_evidence=candidate,
        request_engine=engine,
        auth_context=None,
        budget=None,
        authorization_confirmed=True,
    )

    conclusion = await SqlInjectionVerificationStrategy().verify(context)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert any(
        parse_qs(urlparse(call["url"]).query).get("q") == ["' OR 1=1--"]
        for call in transport.calls
    )
    assert len(conclusion.request_ids) >= 2
