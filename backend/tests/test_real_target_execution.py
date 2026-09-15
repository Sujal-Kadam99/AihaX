"""AihaX Phase 5 Real-Target Execution & End-to-End Proof on TCP Socket."""

import asyncio
import socket
import pytest
from aiohttp import web

from backend.core.check_registry import registry
from backend.core.scope_validator import ScopeValidator
from backend.execution.baseline import BaselineCaptureEngine
from backend.execution.canary import CanaryGenerator
from backend.execution.differential import ReflectionContext, ResponseDifferentialEngine
from backend.execution.mutation_engine import MutationStrategy, ParameterMutationEngine
from backend.execution.parameter_discovery import ParameterDiscoveryEngine
from backend.execution.parameter_model import DiscoveredParameter, ParameterLocation, ParameterSource, ParameterType
from backend.recon.models import DiscoveredEndpoint, DiscoverySource, EndpointType
from backend.services.campaign_executor import CampaignExecutor, CampaignMode, CampaignRequestBudget
from backend.services.request_engine import AiohttpTransport, RequestEngine, RequestSpec, RequestTimeout
from backend.tests.fixtures.security_lab.lab_server import create_security_lab_app


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def live_security_lab_server():
    """Starts the real Security Lab HTTP server on a live loopback TCP port."""
    app = create_security_lab_app()
    runner = web.AppRunner(app)
    await runner.setup()
    port = get_free_port()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    base_url = f"http://127.0.0.1:{port}"
    try:
        yield base_url
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_real_parameter_discovery_and_baseline_capture(live_security_lab_server):
    base_url = live_security_lab_server
    scope = ScopeValidator(in_scope_assets=["127.0.0.1"])

    transport = AiohttpTransport()
    engine = RequestEngine(scope_validator=scope, transport=transport)

    endpoint = DiscoveredEndpoint(
        endpoint_id="ep-search",
        url=f"{base_url}/search_dynamic?q=welcome",
        path="/search_dynamic",
        method="GET",
        endpoint_type=EndpointType.PAGE,
        source=DiscoverySource.HTML_CRAWL,
        parameters=[],
        auth_required="PUBLIC",
        content_type="text/html",
        status_code=200,
        is_api=False,
        is_graphql=False,
        is_upload=False,
        discovered_at="2026-08-28T00:00:00Z",
    )

    # 1. Parameter Discovery
    params = ParameterDiscoveryEngine.discover_parameters(endpoint)
    assert len(params) == 1
    assert params[0].name == "q"
    assert params[0].location == ParameterLocation.QUERY
    assert params[0].baseline_value == "welcome"

    # 2. Baseline Capture
    baseline = await BaselineCaptureEngine.capture_baseline(engine, endpoint, params)
    assert baseline is not None
    assert baseline.status_code == 200
    assert "text/html" in baseline.content_type
    assert len(baseline.body_hash) == 64
    assert len(baseline.structure_fingerprint) == 16
    assert "welcome" in baseline.body_preview


@pytest.mark.asyncio
async def test_real_parameter_mutation_and_differential_verification(live_security_lab_server):
    base_url = live_security_lab_server
    scope = ScopeValidator(in_scope_assets=["127.0.0.1"])

    transport = AiohttpTransport()
    engine = RequestEngine(scope_validator=scope, transport=transport)

    # ----------------------------------------------------
    # Case A: Real XSS Reflection vs Escaped Negative Control
    # ----------------------------------------------------
    ep_vuln = DiscoveredEndpoint(
        endpoint_id="ep-xss-vuln",
        url=f"{base_url}/search_dynamic?q=test",
        path="/search_dynamic",
        method="GET",
        endpoint_type=EndpointType.PAGE,
        source=DiscoverySource.HTML_CRAWL,
        parameters=["q"],
        auth_required="PUBLIC",
        content_type="text/html",
        status_code=200,
        is_api=False,
        is_graphql=False,
        is_upload=False,
        discovered_at="2026-08-28T00:00:00Z",
    )
    param_xss = DiscoveredParameter(
        parameter_id="p-xss",
        endpoint_url=ep_vuln.url,
        method="GET",
        name="q",
        location=ParameterLocation.QUERY,
        param_type=ParameterType.STRING,
        source=ParameterSource.URL_QUERY,
        provenance="Query string",
        baseline_value="test",
    )
    canary_xss = CanaryGenerator.generate_reflection_canary("C037")

    base_vuln = await BaselineCaptureEngine.capture_baseline(engine, ep_vuln, [param_xss])
    spec_vuln, mut_vuln = ParameterMutationEngine.create_mutated_request(ep_vuln, param_xss, canary_xss)
    ev_vuln = await engine.execute(spec_vuln)
    diff_vuln = ResponseDifferentialEngine.analyze_differential(base_vuln, ev_vuln, canary_xss, mut_vuln)

    assert diff_vuln.is_candidate is True
    assert diff_vuln.reflection_detected is True
    assert diff_vuln.reflection_context == ReflectionContext.RAW_HTML
    assert diff_vuln.confidence >= 80

    # Negative control: HTML-Escaped Endpoint
    ep_safe = DiscoveredEndpoint(
        endpoint_id="ep-xss-safe",
        url=f"{base_url}/search_safe_escape?q=test",
        path="/search_safe_escape",
        method="GET",
        endpoint_type=EndpointType.PAGE,
        source=DiscoverySource.HTML_CRAWL,
        parameters=["q"],
        auth_required="PUBLIC",
        content_type="text/html",
        status_code=200,
        is_api=False,
        is_graphql=False,
        is_upload=False,
        discovered_at="2026-08-28T00:00:00Z",
    )
    base_safe = await BaselineCaptureEngine.capture_baseline(engine, ep_safe, [param_xss])
    spec_safe, mut_safe = ParameterMutationEngine.create_mutated_request(ep_safe, param_xss, canary_xss)
    ev_safe = await engine.execute(spec_safe)
    diff_safe = ResponseDifferentialEngine.analyze_differential(base_safe, ev_safe, canary_xss, mut_safe)

    assert diff_safe.is_candidate is False
    assert diff_safe.reflection_context == ReflectionContext.HTML_ENCODED

    # ----------------------------------------------------
    # Case B: Real Math Canary vs Static Text Negative Control
    # ----------------------------------------------------
    ep_math_vuln = DiscoveredEndpoint(
        endpoint_id="ep-math-vuln",
        url=f"{base_url}/calc_dynamic?expr=1",
        path="/calc_dynamic",
        method="GET",
        endpoint_type=EndpointType.PAGE,
        source=DiscoverySource.HTML_CRAWL,
        parameters=["expr"],
        auth_required="PUBLIC",
        content_type="text/html",
        status_code=200,
        is_api=False,
        is_graphql=False,
        is_upload=False,
        discovered_at="2026-08-28T00:00:00Z",
    )
    param_math = DiscoveredParameter(
        parameter_id="p-math",
        endpoint_url=ep_math_vuln.url,
        method="GET",
        name="expr",
        location=ParameterLocation.QUERY,
        param_type=ParameterType.STRING,
        source=ParameterSource.URL_QUERY,
        provenance="Query string",
        baseline_value="1",
    )
    canary_math = CanaryGenerator.generate_arithmetic_canary("C027")

    base_math = await BaselineCaptureEngine.capture_baseline(engine, ep_math_vuln, [param_math])
    spec_math, mut_math = ParameterMutationEngine.create_mutated_request(ep_math_vuln, param_math, canary_math)
    ev_math = await engine.execute(spec_math)
    diff_math = ResponseDifferentialEngine.analyze_differential(base_math, ev_math, canary_math, mut_math)

    assert diff_math.is_candidate is True
    assert diff_math.canary_signal_matched is True

    # ----------------------------------------------------
    # Case C: SQL Syntax Error vs Generic 500
    # ----------------------------------------------------
    ep_sqli = DiscoveredEndpoint(
        endpoint_id="ep-sqli",
        url=f"{base_url}/sql_syntax_error?id=1",
        path="/sql_syntax_error",
        method="GET",
        endpoint_type=EndpointType.API,
        source=DiscoverySource.OPENAPI_SPEC,
        parameters=["id"],
        auth_required="PUBLIC",
        content_type="application/json",
        status_code=200,
        is_api=True,
        is_graphql=False,
        is_upload=False,
        discovered_at="2026-08-28T00:00:00Z",
    )
    param_sqli = DiscoveredParameter(
        parameter_id="p-sqli",
        endpoint_url=ep_sqli.url,
        method="GET",
        name="id",
        location=ParameterLocation.QUERY,
        param_type=ParameterType.INTEGER,
        source=ParameterSource.URL_QUERY,
        provenance="Query string",
        baseline_value="1",
    )
    canary_sqli = CanaryGenerator.generate_sql_syntax_canary("C023")

    base_sqli = await BaselineCaptureEngine.capture_baseline(engine, ep_sqli, [param_sqli])
    spec_sqli, mut_sqli = ParameterMutationEngine.create_mutated_request(ep_sqli, param_sqli, canary_sqli)
    ev_sqli = await engine.execute(spec_sqli)
    diff_sqli = ResponseDifferentialEngine.analyze_differential(base_sqli, ev_sqli, canary_sqli, mut_sqli)

    assert diff_sqli.is_candidate is True
    assert diff_sqli.syntax_error_detected is True

    # Generic 500 Error Rejection
    ep_gen500 = DiscoveredEndpoint(
        endpoint_id="ep-gen500",
        url=f"{base_url}/generic_error_500?val=clean",
        path="/generic_error_500",
        method="GET",
        endpoint_type=EndpointType.API,
        source=DiscoverySource.OPENAPI_SPEC,
        parameters=["val"],
        auth_required="PUBLIC",
        content_type="text/plain",
        status_code=200,
        is_api=True,
        is_graphql=False,
        is_upload=False,
        discovered_at="2026-08-28T00:00:00Z",
    )
    param_gen500 = DiscoveredParameter(
        parameter_id="p-gen500",
        endpoint_url=ep_gen500.url,
        method="GET",
        name="val",
        location=ParameterLocation.QUERY,
        param_type=ParameterType.STRING,
        source=ParameterSource.URL_QUERY,
        provenance="Query string",
        baseline_value="clean",
    )
    base_gen500 = await BaselineCaptureEngine.capture_baseline(engine, ep_gen500, [param_gen500])
    spec_gen500, mut_gen500 = ParameterMutationEngine.create_mutated_request(
        ep_gen500,
        param_gen500,
        canary_sqli,
        custom_payload="trigger_error",
    )
    ev_gen500 = await engine.execute(spec_gen500)
    diff_gen500 = ResponseDifferentialEngine.analyze_differential(base_gen500, ev_gen500, canary_sqli, mut_gen500)

    # Generic 500 without database error signature MUST be rejected
    assert diff_gen500.is_candidate is False
    assert diff_gen500.generic_500_detected is True


@pytest.mark.asyncio
async def test_campaign_executor_plan_only_mode(live_security_lab_server):
    base_url = live_security_lab_server
    scope = ScopeValidator(in_scope_assets=["127.0.0.1"])

    transport = AiohttpTransport()
    executor = CampaignExecutor(
        scope_validator=scope,
        transport=transport,
        campaign_budget=200,
    )

    result = await executor.execute_campaign(
        campaign_id="cmp-plan-only",
        target_url=base_url,
        mode=CampaignMode.PLAN_ONLY,
    )

    assert result.mode == "PLAN_ONLY"
    assert result.execution_graph is not None
    assert result.parameters_discovered >= 1
    assert result.checks_planned >= 1
    assert result.checks_executed == 0
    assert result.candidates_count == 0
