"""Unit and Integration tests for Phase 5.1-C Passive Discovery Providers."""

import asyncio
import json
import pytest
from unittest.mock import patch

from backend.core.scope_validator import ScopeValidator
from backend.services.discovery.alienvault_provider import AlienVaultProvider
from backend.services.discovery.crtsh_provider import CRTShProvider
from backend.services.discovery.dns_provider import DNSProvider
from backend.services.discovery.wayback_provider import WaybackProvider
from backend.services.request_engine import (
    MockTransport,
    RawResponse,
    RequestEngine,
    RequestSpec,
)


@pytest.fixture
def mock_transport():
    return MockTransport()


@pytest.fixture
def scope_validator_all_allowed():
    # Allows both target domains and public passive provider endpoints
    return ScopeValidator(
        in_scope_assets=[
            "example.com",
            "*.example.com",
            "crt.sh",
            "*.crt.sh",
            "web.archive.org",
            "*.archive.org",
            "otx.alienvault.com",
            "*.alienvault.com",
        ]
    )


@pytest.fixture
def request_engine(scope_validator_all_allowed, mock_transport):
    return RequestEngine(
        scope_validator=scope_validator_all_allowed,
        rate_limit_rps=50,
        max_concurrency=10,
        transport=mock_transport,
    )


# ==============================================================================
# 1-4. CRT.SH PROVIDER TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_crtsh_returns_subdomains(request_engine, mock_transport):
    """Scenario 1: CRT.sh queries CT logs and returns normalized subdomains."""
    sample_crtsh_data = [
        {"id": 1, "name_value": "api.example.com", "common_name": "api.example.com"},
        {"id": 2, "name_value": "auth.example.com", "common_name": "auth.example.com"},
        {"id": 3, "name_value": "example.com", "common_name": "example.com"},
    ]
    mock_transport.add_route("crt.sh", status=200, body=json.dumps(sample_crtsh_data))

    provider = CRTShProvider()
    items = await provider.discover("example.com", request_engine)

    assert len(items) == 3
    values = [item.normalized_value for item in items]
    assert "api.example.com" in values
    assert "auth.example.com" in values
    assert "example.com" in values
    assert all(item.source_code == "SRC_CRTSH" for item in items)


@pytest.mark.asyncio
async def test_crtsh_deduplicates_domains(request_engine, mock_transport):
    """Scenario 2: CRT.sh deduplicates duplicate domain occurrences in CT entries."""
    sample_crtsh_data = [
        {"id": 1, "name_value": "api.example.com\nAPI.EXAMPLE.COM", "common_name": "api.example.com"},
        {"id": 2, "name_value": "api.example.com", "common_name": "api.example.com"},
        {"id": 3, "name_value": "api.example.com.", "common_name": "api.example.com"},
    ]
    mock_transport.add_route("crt.sh", status=200, body=json.dumps(sample_crtsh_data))

    provider = CRTShProvider()
    items = await provider.discover("example.com", request_engine)

    assert len(items) == 1
    assert items[0].normalized_value == "api.example.com"


@pytest.mark.asyncio
async def test_crtsh_handles_wildcard_sans(request_engine, mock_transport):
    """Scenario 3: CRT.sh strips wildcard prefixes (*.sub.example.com -> sub.example.com)."""
    sample_crtsh_data = [
        {"id": 1, "name_value": "*.sub.example.com\n*.example.com", "common_name": "*.example.com"},
    ]
    mock_transport.add_route("crt.sh", status=200, body=json.dumps(sample_crtsh_data))

    provider = CRTShProvider()
    items = await provider.discover("example.com", request_engine)

    values = [item.normalized_value for item in items]
    assert "sub.example.com" in values
    assert "example.com" in values
    assert not any(v.startswith("*") for v in values)


@pytest.mark.asyncio
async def test_crtsh_rejects_malformed_domains(request_engine, mock_transport):
    """Scenario 4: CRT.sh safely ignores malformed domain entries without crashing."""
    sample_crtsh_data = [
        {"id": 1, "name_value": "valid.example.com", "common_name": "valid.example.com"},
        {"id": 2, "name_value": "bad domain with spaces", "common_name": ""},
        {"id": 3, "name_value": "a" * 70 + ".com", "common_name": ""},
        {"id": 4, "name_value": "unrelated.org", "common_name": "unrelated.org"},
    ]
    mock_transport.add_route("crt.sh", status=200, body=json.dumps(sample_crtsh_data))

    provider = CRTShProvider()
    items = await provider.discover("example.com", request_engine)

    assert len(items) == 1
    assert items[0].normalized_value == "valid.example.com"


# ==============================================================================
# 5-9. WAYBACK PROVIDER TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_wayback_returns_and_normalizes_urls(request_engine, mock_transport):
    """Scenarios 5, 6, 7, 8: Wayback retrieves, normalizes, sorts query params, and deduplicates."""
    cdx_data = [
        ["original"],
        ["http://EXAMPLE.COM:80/api/v1?b=2&a=1"],
        ["https://example.com/api//v1?a=1&b=2#frag"],
        ["https://admin.example.com/login?redirect=%2Fdashboard"],
    ]
    mock_transport.add_route("web.archive.org", status=200, body=json.dumps(cdx_data))

    provider = WaybackProvider()
    items = await provider.discover("example.com", request_engine)

    # Check endpoints and host items
    endpoint_urls = [item.endpoint_url for item in items if item.asset_type == "URL"]
    assert "https://example.com/api/v1?a=1&b=2" in endpoint_urls or "http://example.com/api/v1?a=1&b=2" in endpoint_urls
    assert "https://admin.example.com/login?redirect=%2Fdashboard" in endpoint_urls
    
    # Query parameters are sorted deterministically
    assert any("a=1&b=2" in str(u) for u in endpoint_urls)

    # Discovered hosts
    host_vals = [item.normalized_value for item in items if item.asset_type in ("DOMAIN", "SUBDOMAIN")]
    assert "example.com" in host_vals
    assert "admin.example.com" in host_vals


@pytest.mark.asyncio
async def test_wayback_does_not_contact_discovered_targets(request_engine, mock_transport):
    """Scenario 9: Wayback provider ONLY communicates with Archive.org, zero calls to target URLs."""
    cdx_data = [
        ["original"],
        ["https://target1.example.com/admin"],
        ["https://target2.example.com/secret"],
    ]
    mock_transport.add_route("web.archive.org", status=200, body=json.dumps(cdx_data))

    provider = WaybackProvider()
    await provider.discover("example.com", request_engine)

    # Verify all transport calls went to web.archive.org
    for call in mock_transport.calls:
        assert "web.archive.org" in call["url"]
        assert "target1.example.com" not in call["url"].split("?")[0]
        assert "target2.example.com" not in call["url"].split("?")[0]


# ==============================================================================
# 10-12. ALIENVAULT PROVIDER TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_alienvault_extracts_passive_dns_and_normalizes_ips(request_engine, mock_transport):
    """Scenarios 10, 11, 12: AlienVault extracts passive DNS, normalizes IPv4 & IPv6."""
    otx_data = {
        "passive_dns": [
            {"hostname": "vpn.example.com", "record_type": "A", "address": "192.168.1.1"},
            {"hostname": "ipv6.example.com", "record_type": "AAAA", "address": "2001:0db8:0000:0000:0000:0000:0000:0001"},
            {"hostname": "cdn.example.com", "record_type": "CNAME", "address": "d123.cloudfront.net"},
        ]
    }
    mock_transport.add_route("otx.alienvault.com", status=200, body=json.dumps(otx_data))

    provider = AlienVaultProvider()
    items = await provider.discover("example.com", request_engine)

    norm_values = [item.normalized_value for item in items]
    assert "vpn.example.com" in norm_values
    assert "192.168.1.1" in norm_values
    assert "2001:db8::1" in norm_values  # RFC 5952 normalized IPv6
    assert "ipv6.example.com" in norm_values


# ==============================================================================
# 13-18. REQUEST ENGINE ROUTING, SCOPE, ERRORS, & TIMEOUTS
# ==============================================================================

@pytest.mark.asyncio
async def test_provider_http_traffic_goes_through_request_engine(request_engine, mock_transport):
    """Scenario 13: All provider traffic is routed through RequestEngine and captured."""
    mock_transport.add_route("crt.sh", status=200, body="[]")

    provider = CRTShProvider()
    await provider.discover("example.com", request_engine)

    assert mock_transport.call_count == 1
    assert "crt.sh" in mock_transport.calls[0]["url"]


@pytest.mark.asyncio
async def test_out_of_scope_provider_request_is_blocked(mock_transport):
    """Scenario 14: When provider domain is not in ScopeValidator, request is blocked."""
    # ScopeValidator that excludes crt.sh
    strict_scope = ScopeValidator(in_scope_assets=["example.com"])
    strict_engine = RequestEngine(scope_validator=strict_scope, transport=mock_transport)

    provider = CRTShProvider()
    items = await provider.discover("example.com", strict_engine)

    assert items == []
    # Zero transport network calls should have been made
    assert mock_transport.call_count == 0


@pytest.mark.asyncio
async def test_authorization_gate_enforced(mock_transport, scope_validator_all_allowed):
    """Scenario 15: If authorization is not confirmed on RequestSpec, transport is blocked."""
    engine = RequestEngine(scope_validator=scope_validator_all_allowed, transport=mock_transport)
    
    spec = RequestSpec(
        url="https://crt.sh/?q=%.example.com&output=json",
        authorization_confirmed=False,
    )
    evidence = await engine.execute(spec)

    assert evidence.response_status is None
    assert evidence.transport_error is not None
    assert evidence.transport_error["error_type"] == "AUTH_MISSING"
    assert mock_transport.call_count == 0


@pytest.mark.asyncio
async def test_provider_timeout_handled_safely(request_engine, mock_transport):
    """Scenario 16: Provider timeout is caught safely and returns empty list."""
    mock_transport.register_handler(
        lambda m, u: "crt.sh" in u,
        asyncio.TimeoutError("Connection timed out"),
    )

    provider = CRTShProvider()
    items = await provider.discover("example.com", request_engine)
    assert items == []


@pytest.mark.asyncio
async def test_provider_http_errors_handled_safely(request_engine, mock_transport):
    """Scenario 17: HTTP 500/502/404 from provider is handled safely."""
    mock_transport.add_route("crt.sh", status=502, body="Bad Gateway")

    provider = CRTShProvider()
    items = await provider.discover("example.com", request_engine)
    assert items == []


@pytest.mark.asyncio
async def test_malformed_provider_json_handled_safely(request_engine, mock_transport):
    """Scenario 18: Non-JSON / malformed HTML error pages from provider don't crash discovery."""
    mock_transport.add_route("crt.sh", status=200, body="<html>Error 504 Gateway Time-out</html>")

    provider = CRTShProvider()
    items = await provider.discover("example.com", request_engine)
    assert items == []


# ==============================================================================
# 19-21. EVIDENCE & PROVENANCE TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_evidence_id_and_provenance_preservation(request_engine, mock_transport):
    """Scenarios 19, 20, 21: Evidence IDs, Request IDs, and raw data are retained."""
    sample_data = [{"id": 42, "name_value": "secure.example.com", "common_name": "secure.example.com"}]
    mock_transport.add_route("crt.sh", status=200, body=json.dumps(sample_data))

    provider = CRTShProvider()
    items = await provider.discover("example.com", request_engine)

    assert len(items) == 1
    item = items[0]

    assert item.request_id is not None
    assert item.request_id.startswith("REQ-")
    assert item.evidence_id is not None
    assert item.evidence_id.startswith("EVD-PASSIVE-")
    assert item.raw_data == sample_data[0]
    assert item.confidence == 90


# ==============================================================================
# 22-23. SECURITY AUDIT: ZERO SUBPROCESS / ZERO SOCKETS
# ==============================================================================

@pytest.mark.asyncio
async def test_security_invariants_no_subprocess_no_raw_sockets(request_engine, mock_transport):
    """Scenarios 22, 23: Providers never invoke subprocesses, nmap, subfinder, or raw sockets."""
    mock_transport.add_route("crt.sh", status=200, body=json.dumps([{"name_value": "api.example.com"}]))

    with patch("subprocess.Popen", side_effect=RuntimeError("SUBPROCESS PROHIBITED")), \
         patch("asyncio.create_subprocess_exec", side_effect=RuntimeError("SUBPROCESS PROHIBITED")), \
         patch("socket.socket", side_effect=RuntimeError("RAW SOCKET PROHIBITED")):

        provider = CRTShProvider()
        items = await provider.discover("example.com", request_engine)
        assert len(items) == 1
        assert items[0].normalized_value == "api.example.com"


# ==============================================================================
# 24-25. SECURITY INVARIANT: DISCOVERED != AUTHORIZED
# ==============================================================================

@pytest.mark.asyncio
async def test_security_invariant_discovered_is_not_authorized(request_engine, mock_transport):
    """Scenarios 24, 25: Discovered items NEVER contain authorization decisions."""
    mock_transport.add_route("crt.sh", status=200, body=json.dumps([{"name_value": "internal.example.com"}]))

    provider = CRTShProvider()
    items = await provider.discover("example.com", request_engine)

    assert len(items) == 1
    item = items[0]
    item_dict = item.to_dict()

    # The provider produces discovery metadata ONLY, not authorization or scope decisions
    assert "active_testing_allowed" not in item_dict
    assert "scope_status" not in item_dict
    assert item.normalized_value == "internal.example.com"


@pytest.mark.asyncio
async def test_dns_provider_processes_passive_records(request_engine):
    """Test DNSProvider parses, normalizes, and extracts passive DNS records without active scanning."""
    sample_records = [
        {"hostname": "api.EXAMPLE.com.", "type": "A", "value": "93.184.216.34"},
        {"hostname": "cdn.example.com", "type": "CNAME", "value": "d123.cloudfront.net"},
        {"hostname": "ipv6.example.com", "type": "AAAA", "value": "2001:0db8:0000:0000:0000:0000:0000:0001"},
    ]
    provider = DNSProvider()
    items = await provider.discover("example.com", request_engine, config={"dns_records": sample_records})

    norm_values = [item.normalized_value for item in items]
    assert "api.example.com" in norm_values
    assert "93.184.216.34" in norm_values
    assert "cdn.example.com" in norm_values
    assert "2001:db8::1" in norm_values
    assert "ipv6.example.com" in norm_values
