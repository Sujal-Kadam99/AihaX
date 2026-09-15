"""Tests for AihaX Phase 5 Parameter Mutation & Differential Engines."""

import html
import json
import pytest

from backend.execution.baseline import BaselineSnapshot
from backend.execution.canary import CanaryCategory, CanaryGenerator
from backend.execution.differential import (
    ReflectionContext,
    ResponseDifferentialEngine,
)
from backend.execution.mutation_engine import (
    MutationStrategy,
    ParameterMutationEngine,
)
from backend.execution.parameter_model import (
    DiscoveredParameter,
    ParameterLocation,
    ParameterSource,
    ParameterType,
)
from backend.recon.models import DiscoverySource, DiscoveredEndpoint, EndpointType
from backend.services.request_engine import RequestEvidence


def make_test_evidence(
    method: str = "GET",
    url: str = "http://example.local",
    status: int = 200,
    headers: dict = None,
    body: str = "",
    duration_ms: float = 10.0,
) -> RequestEvidence:
    return RequestEvidence(
        request_id="REQ-test-1",
        timestamp="2026-08-28T00:00:00Z",
        method=method,
        url=url,
        request_headers={},
        request_body=None,
        response_status=status,
        response_headers=headers or {},
        response_body=body,
        response_size=len(body.encode("utf-8")),
        duration_ms=duration_ms,
        truncated=False,
        redirect_chain=[],
        scope_decision={"allowed": True},
        transport_error=None,
        request_hash="reqhash",
        response_hash="reshash",
        success=True,
    )


def test_parameter_mutation_query_replace_and_append():
    ep = DiscoveredEndpoint(
        endpoint_id="ep-1",
        url="http://example.local/search?q=original",
        path="/search",
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
    param = DiscoveredParameter(
        parameter_id="p-1",
        endpoint_url=ep.url,
        method="GET",
        name="q",
        location=ParameterLocation.QUERY,
        param_type=ParameterType.STRING,
        source=ParameterSource.URL_QUERY,
        provenance="URL query string",
        baseline_value="original",
    )
    canary = CanaryGenerator.generate_reflection_canary("C037")

    # Replace
    spec_rep, mut_rep = ParameterMutationEngine.create_mutated_request(
        endpoint=ep,
        parameter=param,
        canary=canary,
        strategy=MutationStrategy.REPLACE,
    )
    from urllib.parse import unquote
    assert f"q={canary.payload}" in unquote(spec_rep.url)
    assert mut_rep.strategy == MutationStrategy.REPLACE

    # Append
    spec_app, mut_app = ParameterMutationEngine.create_mutated_request(
        endpoint=ep,
        parameter=param,
        canary=canary,
        strategy=MutationStrategy.APPEND,
    )
    assert f"q=original{canary.payload}" in unquote(spec_app.url)


def test_parameter_mutation_json_body():
    ep = DiscoveredEndpoint(
        endpoint_id="ep-2",
        url="http://example.local/api/v1/update",
        path="/api/v1/update",
        method="POST",
        endpoint_type=EndpointType.API,
        source=DiscoverySource.OPENAPI_SPEC,
        parameters=[],
        auth_required="PUBLIC",
        content_type="application/json",
        status_code=200,
        is_api=True,
        is_graphql=False,
        is_upload=False,
        discovered_at="2026-08-28T00:00:00Z",
    )
    param = DiscoveredParameter(
        parameter_id="p-2",
        endpoint_url=ep.url,
        method="POST",
        name="score",
        location=ParameterLocation.JSON,
        param_type=ParameterType.INTEGER,
        source=ParameterSource.JSON_BODY,
        provenance="JSON body field",
        baseline_value=10,
        json_path="$.score",
    )
    canary = CanaryGenerator.generate_arithmetic_canary("C027")

    spec, mut = ParameterMutationEngine.create_mutated_request(
        endpoint=ep,
        parameter=param,
        canary=canary,
        strategy=MutationStrategy.REPLACE,
    )
    parsed_body = json.loads(spec.body.decode("utf-8"))
    assert parsed_body["score"] == canary.payload


def test_response_differential_xss_reflection_detected():
    canary = CanaryGenerator.generate_reflection_canary("C037")
    param = DiscoveredParameter(
        parameter_id="p-3",
        endpoint_url="http://example.local/search",
        method="GET",
        name="q",
        location=ParameterLocation.QUERY,
        param_type=ParameterType.STRING,
        source=ParameterSource.URL_QUERY,
        provenance="Query",
    )
    _, mutation = ParameterMutationEngine.create_mutated_request(
        endpoint=DiscoveredEndpoint(
            endpoint_id="ep-3",
            url="http://example.local/search",
            path="/search",
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
        ),
        parameter=param,
        canary=canary,
    )

    base_ev = make_test_evidence(
        method="GET",
        url="http://example.local/search?q=test",
        status=200,
        headers={"Content-Type": "text/html"},
        body="<html><body><h1>No Results</h1></body></html>",
        duration_ms=15.0,
    )
    baseline = BaselineSnapshot(
        baseline_id="b-1",
        endpoint_url="http://example.local/search",
        method="GET",
        status_code=200,
        headers={"content-type": "text/html"},
        content_type="text/html",
        body_hash="hash1",
        body_length=len(base_ev.response_body),
        response_time_ms=15.0,
        body_preview=base_ev.response_body,
        structure_fingerprint="fp1",
        is_redirect=False,
        redirect_target=None,
        auth_context_name=None,
        request_evidence=base_ev,
    )

    # 1. Raw reflection (Vulnerable)
    vuln_ev = make_test_evidence(
        method="GET",
        url=f"http://example.local/search?q={canary.payload}",
        status=200,
        headers={"Content-Type": "text/html"},
        body=f"<html><body><h1>Results for {canary.payload}</h1></body></html>",
        duration_ms=16.0,
    )
    diff = ResponseDifferentialEngine.analyze_differential(baseline, vuln_ev, canary, mutation)
    assert diff.is_candidate is True
    assert diff.reflection_detected is True
    assert diff.reflection_context == ReflectionContext.RAW_HTML
    assert diff.confidence >= 80

    # 2. HTML Encoded Reflection (Defended False-Positive)
    encoded_ev = make_test_evidence(
        method="GET",
        url=f"http://example.local/search?q={canary.payload}",
        status=200,
        headers={"Content-Type": "text/html"},
        body=f"<html><body><h1>Results for {html.escape(canary.payload)}</h1></body></html>",
        duration_ms=16.0,
    )
    diff_encoded = ResponseDifferentialEngine.analyze_differential(baseline, encoded_ev, canary, mutation)
    assert diff_encoded.is_candidate is False
    assert diff_encoded.reflection_context == ReflectionContext.HTML_ENCODED


def test_response_differential_generic_500_rejected():
    canary = CanaryGenerator.generate_sql_syntax_canary("C023")
    param = DiscoveredParameter(
        parameter_id="p-4",
        endpoint_url="http://example.local/items",
        method="GET",
        name="id",
        location=ParameterLocation.QUERY,
        param_type=ParameterType.INTEGER,
        source=ParameterSource.URL_QUERY,
        provenance="Query",
    )
    _, mutation = ParameterMutationEngine.create_mutated_request(
        endpoint=DiscoveredEndpoint(
            endpoint_id="ep-4",
            url="http://example.local/items",
            path="/items",
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
        ),
        parameter=param,
        canary=canary,
    )

    base_ev = make_test_evidence(
        method="GET",
        url="http://example.local/items?id=1",
        status=200,
        headers={"Content-Type": "application/json"},
        body='{"item": "shoes"}',
        duration_ms=10.0,
    )
    baseline = BaselineSnapshot(
        baseline_id="b-2",
        endpoint_url="http://example.local/items",
        method="GET",
        status_code=200,
        headers={"content-type": "application/json"},
        content_type="application/json",
        body_hash="hash2",
        body_length=len(base_ev.response_body),
        response_time_ms=10.0,
        body_preview=base_ev.response_body,
        structure_fingerprint="fp2",
        is_redirect=False,
        redirect_target=None,
        auth_context_name=None,
        request_evidence=base_ev,
    )

    # Generic 500 without database error syntax
    generic_500_ev = make_test_evidence(
        method="GET",
        url="http://example.local/items?id='",
        status=500,
        headers={"Content-Type": "text/plain"},
        body="Internal Server Error: Unhandled application exception",
        duration_ms=12.0,
    )
    diff_500 = ResponseDifferentialEngine.analyze_differential(baseline, generic_500_ev, canary, mutation)
    assert diff_500.is_candidate is False
    assert diff_500.generic_500_detected is True
    assert diff_500.syntax_error_detected is False


def test_response_differential_negative_control_cancellation():
    canary = CanaryGenerator.generate_arithmetic_canary("C027")
    param = DiscoveredParameter(
        parameter_id="p-5",
        endpoint_url="http://example.local/calc",
        method="GET",
        name="expr",
        location=ParameterLocation.QUERY,
        param_type=ParameterType.STRING,
        source=ParameterSource.URL_QUERY,
        provenance="Query",
    )
    _, mutation = ParameterMutationEngine.create_mutated_request(
        endpoint=DiscoveredEndpoint(
            endpoint_id="ep-5",
            url="http://example.local/calc",
            path="/calc",
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
        ),
        parameter=param,
        canary=canary,
    )

    baseline = BaselineSnapshot(
        baseline_id="b-3",
        endpoint_url="http://example.local/calc",
        method="GET",
        status_code=200,
        headers={"content-type": "text/html"},
        content_type="text/html",
        body_hash="hash3",
        body_length=50,
        response_time_ms=10.0,
        body_preview="Input: none",
        structure_fingerprint="fp3",
        is_redirect=False,
        redirect_target=None,
        auth_context_name=None,
        request_evidence=make_test_evidence(
            method="GET",
            url="http://example.local/calc",
            status=200,
            headers={},
            body="Input: none",
            duration_ms=10.0,
        ),
    )

    # Mutated output contains calculated result
    mut_ev = make_test_evidence(
        method="GET",
        url="http://example.local/calc?expr=$((1000*20))",
        status=200,
        headers={},
        body=f"Result: {canary.expected_signal}",
        duration_ms=10.0,
    )
    # Control output ALSO contains the signal (e.g. static fixture)
    ctrl_ev = make_test_evidence(
        method="GET",
        url="http://example.local/calc?expr=static",
        status=200,
        headers={},
        body=f"Static: {canary.negative_control_expected}",
        duration_ms=10.0,
    )

    diff = ResponseDifferentialEngine.analyze_differential(
        baseline,
        mut_ev,
        canary,
        mutation,
        control_evidence=ctrl_ev,
    )
    # Control matched, so is_candidate must be False
    assert diff.control_signal_matched is True
    assert diff.is_candidate is False
