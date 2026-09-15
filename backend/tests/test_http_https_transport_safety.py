"""Tests for HTTP and HTTPS Transport Support and Security Scope Enforcement."""

import pytest
from backend.core.scope_validator import ScopeValidator, ScopeStatus
from backend.services.request_engine import (
    MockTransport,
    RawResponse,
    RequestEngine,
    RequestSpec,
    TransportError,
)


@pytest.fixture
def multi_scheme_scope_validator():
    return ScopeValidator(
        in_scope_assets=[
            "https://*.zomato.com/*",
            "http://*.zomato.com/*",
            "*.zomato.com",
            "zomato.com",
        ],
        out_of_scope_assets=[
            "https://evil.com/*",
            "http://evil.com/*",
            "*.attacker.com",
            "*.blinkit.com",
        ],
        allowed_schemes=["http", "https"],
        allowed_ports=[80, 443],
        excluded_ports=[22, 25, 445, 3389, 8080],
    )


@pytest.mark.asyncio
async def test_authorized_http_url(multi_scheme_scope_validator):
    transport = MockTransport()
    transport.register_response(
        url_prefix="http://www.zomato.com/robots.txt",
        status_code=200,
        headers={"content-type": "text/plain"},
        body=b"User-agent: *\nDisallow: /admin",
    )
    engine = RequestEngine(scope_validator=multi_scheme_scope_validator, transport=transport)

    spec = RequestSpec(url="http://www.zomato.com/robots.txt", authorization_confirmed=True)
    ev = await engine.execute(spec)

    assert ev.success is True
    assert ev.response_status == 200
    assert "User-agent: *" in ev.response_body
    assert transport.call_count == 1


@pytest.mark.asyncio
async def test_authorized_https_url(multi_scheme_scope_validator):
    transport = MockTransport()
    transport.register_response(
        url_prefix="https://api.zomato.com/v2/restaurants",
        status_code=200,
        headers={"content-type": "application/json"},
        body=b'{"restaurants":[]}',
    )
    engine = RequestEngine(scope_validator=multi_scheme_scope_validator, transport=transport)

    spec = RequestSpec(url="https://api.zomato.com/v2/restaurants", authorization_confirmed=True)
    ev = await engine.execute(spec)

    assert ev.success is True
    assert ev.response_status == 200
    assert ev.transport_error is None
    assert transport.call_count == 1


@pytest.mark.asyncio
async def test_out_of_scope_http_url(multi_scheme_scope_validator):
    transport = MockTransport()
    engine = RequestEngine(scope_validator=multi_scheme_scope_validator, transport=transport)

    spec = RequestSpec(url="http://evil.com/leak", authorization_confirmed=True)
    ev = await engine.execute(spec)

    assert ev.success is False
    assert ev.transport_error["error_type"] == "SCOPE_DENIED"
    assert transport.call_count == 0  # Zero network bytes


@pytest.mark.asyncio
async def test_out_of_scope_https_url(multi_scheme_scope_validator):
    transport = MockTransport()
    engine = RequestEngine(scope_validator=multi_scheme_scope_validator, transport=transport)

    spec = RequestSpec(url="https://evil.com/leak", authorization_confirmed=True)
    ev = await engine.execute(spec)

    assert ev.success is False
    assert ev.transport_error["error_type"] == "SCOPE_DENIED"
    assert transport.call_count == 0  # Zero network bytes


@pytest.mark.asyncio
async def test_https_to_out_of_scope_redirect_blocked(multi_scheme_scope_validator):
    transport = MockTransport()
    transport.register_response(
        url_prefix="https://www.zomato.com/oauth/callback",
        status_code=302,
        headers={"location": "https://attacker.com/steal_token"},
        body="",
    )
    engine = RequestEngine(scope_validator=multi_scheme_scope_validator, transport=transport)

    spec = RequestSpec(url="https://www.zomato.com/oauth/callback", follow_redirects=True, authorization_confirmed=True)
    ev = await engine.execute(spec)

    assert ev.success is False
    assert ev.transport_error["error_type"] == "REDIRECT_BLOCKED"
    assert transport.call_count == 1  # Only initial in-scope request sent, out-of-scope hop blocked


@pytest.mark.asyncio
async def test_http_to_out_of_scope_redirect_blocked(multi_scheme_scope_validator):
    transport = MockTransport()
    transport.register_response(
        url_prefix="http://www.zomato.com/legacy_redirect",
        status_code=301,
        headers={"location": "http://evil.com/phish"},
        body="",
    )
    engine = RequestEngine(scope_validator=multi_scheme_scope_validator, transport=transport)

    spec = RequestSpec(url="http://www.zomato.com/legacy_redirect", follow_redirects=True, authorization_confirmed=True)
    ev = await engine.execute(spec)

    assert ev.success is False
    assert ev.transport_error["error_type"] == "REDIRECT_BLOCKED"
    assert transport.call_count == 1


@pytest.mark.asyncio
async def test_excluded_port_blocked(multi_scheme_scope_validator):
    transport = MockTransport()
    engine = RequestEngine(scope_validator=multi_scheme_scope_validator, transport=transport)

    spec = RequestSpec(url="https://www.zomato.com:22/ssh", authorization_confirmed=True)
    ev = await engine.execute(spec)

    assert ev.success is False
    assert ev.transport_error["error_type"] == "SCOPE_DENIED"
    assert transport.call_count == 0


@pytest.mark.asyncio
async def test_unauthorized_request_blocked(multi_scheme_scope_validator):
    transport = MockTransport()
    engine = RequestEngine(scope_validator=multi_scheme_scope_validator, transport=transport)

    spec = RequestSpec(url="https://www.zomato.com/api", authorization_confirmed=False)
    ev = await engine.execute(spec)

    assert ev.success is False
    assert ev.transport_error["error_type"] == "AUTH_MISSING"
    assert transport.call_count == 0


@pytest.mark.asyncio
async def test_tls_transport_failure_handled_safely(multi_scheme_scope_validator):
    transport = MockTransport()
    transport.register_handler(
        matcher=lambda m, u: "tls-error" in u,
        response=Exception("SSL: CERTIFICATE_VERIFY_FAILED (_ssl.c:1000)"),
    )
    engine = RequestEngine(scope_validator=multi_scheme_scope_validator, transport=transport)

    spec = RequestSpec(url="https://www.zomato.com/tls-error", authorization_confirmed=True)
    ev = await engine.execute(spec)

    assert ev.success is False
    assert ev.transport_error is not None
    assert ev.transport_error["error_type"] in ("TLS_ERROR", "TRANSPORT_ERROR")
    assert "CERTIFICATE_VERIFY_FAILED" in ev.transport_error["message"]
