"""Tests for AihaX Phase 5 Parameter Discovery Engine."""

import pytest

from backend.execution.parameter_discovery import ParameterDiscoveryEngine
from backend.execution.parameter_model import (
    DiscoveredParameter,
    ParameterLocation,
    ParameterSource,
    ParameterType,
)
from backend.recon.models import DiscoverySource, DiscoveredEndpoint, EndpointType


def test_discover_query_parameters_from_url():
    ep = DiscoveredEndpoint(
        endpoint_id="ep-1",
        url="http://example.local/search?q=security&page=2&debug=true",
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
    )
    params = ParameterDiscoveryEngine.discover_parameters(ep)
    param_map = {p.name: p for p in params}

    assert "q" in param_map
    assert param_map["q"].location == ParameterLocation.QUERY
    assert param_map["q"].baseline_value == "security"
    assert param_map["q"].param_type == ParameterType.STRING

    assert "page" in param_map
    assert param_map["page"].baseline_value == "2"
    assert param_map["page"].param_type == ParameterType.INTEGER

    assert "debug" in param_map
    assert param_map["debug"].baseline_value == "true"
    assert param_map["debug"].param_type == ParameterType.BOOLEAN


def test_discover_path_parameters_from_template():
    ep = DiscoveredEndpoint(
        endpoint_id="ep-2",
        url="http://example.local/api/v1/accounts/{accountId}",
        path="/api/v1/accounts/{accountId}",
        method="GET",
        endpoint_type=EndpointType.API,
        source=DiscoverySource.OPENAPI_SPEC,
        parameters=[],
        auth_required="AUTHENTICATION_REQUIRED",
        content_type="application/json",
        status_code=200,
        is_api=True,
        is_graphql=False,
        is_upload=False,
        discovered_at="2026-08-28T00:00:00Z",
    )
    params = ParameterDiscoveryEngine.discover_parameters(ep)
    assert len(params) == 1
    assert params[0].name == "accountId"
    assert params[0].location == ParameterLocation.PATH
    assert params[0].is_required is True


def test_discover_html_form_parameters():
    html_content = """
    <html>
        <body>
            <form action="/login" method="POST">
                <input type="text" name="username" value="admin" />
                <input type="password" name="password" />
                <select name="role">
                    <option value="user" selected>User</option>
                    <option value="manager">Manager</option>
                </select>
                <textarea name="notes">Initial note</textarea>
            </form>
            <form action="/upload" method="POST" enctype="multipart/form-data">
                <input type="file" name="avatar" />
            </form>
        </body>
    </html>
    """
    ep = DiscoveredEndpoint(
        endpoint_id="ep-3",
        url="http://example.local/login",
        path="/login",
        method="POST",
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
    params = ParameterDiscoveryEngine.discover_parameters(ep, raw_html=html_content)
    names = {p.name: p for p in params}

    assert "username" in names
    assert names["username"].location == ParameterLocation.FORM
    assert names["username"].baseline_value == "admin"

    assert "password" in names
    assert names["password"].location == ParameterLocation.FORM

    assert "role" in names
    assert names["role"].location == ParameterLocation.FORM
    assert names["role"].baseline_value == "user"

    assert "notes" in names
    assert names["notes"].location == ParameterLocation.FORM
    assert names["notes"].baseline_value == "Initial note"

    assert "avatar" in names
    assert names["avatar"].location == ParameterLocation.MULTIPART
    assert names["avatar"].param_type == ParameterType.FILE


def test_discover_json_body_parameters():
    sample_json = {
        "user_id": 42,
        "email": "auditor@example.com",
        "is_active": True,
        "profile": {
            "display_name": "Auditor",
            "score": 100,
        }
    }
    ep = DiscoveredEndpoint(
        endpoint_id="ep-4",
        url="http://example.local/api/v1/users",
        path="/api/v1/users",
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
    params = ParameterDiscoveryEngine.discover_parameters(ep, observed_json=sample_json)
    param_map = {p.name: p for p in params}

    assert "user_id" in param_map
    assert param_map["user_id"].location == ParameterLocation.JSON
    assert param_map["user_id"].param_type == ParameterType.INTEGER
    assert param_map["user_id"].baseline_value == 42

    assert "email" in param_map
    assert param_map["email"].location == ParameterLocation.JSON
    assert param_map["email"].baseline_value == "auditor@example.com"

    assert "display_name" in param_map
    assert param_map["display_name"].json_path == "$.profile.display_name"


def test_no_synthetic_parameters_invented_without_evidence():
    ep = DiscoveredEndpoint(
        endpoint_id="ep-5",
        url="http://example.local/static/style.css",
        path="/static/style.css",
        method="GET",
        endpoint_type=EndpointType.STATIC_ASSET,
        source=DiscoverySource.HTML_CRAWL,
        parameters=[],
        auth_required="PUBLIC",
        content_type="text/css",
        status_code=200,
        is_api=False,
        is_graphql=False,
        is_upload=False,
        discovered_at="2026-08-28T00:00:00Z",
    )
    params = ParameterDiscoveryEngine.discover_parameters(ep)
    assert len(params) == 0
