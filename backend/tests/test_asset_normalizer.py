"""Unit tests for Deterministic Asset, Domain, IP, URL, and Query Parameter Normalization."""

import pytest
from unittest.mock import patch

from backend.services.discovery.normalizer import (
    normalize_domain,
    normalize_ip,
    normalize_url,
    normalize_query,
    normalize_asset,
    AssetType,
)


# ==============================================================================
# 1. DOMAIN NORMALIZATION TESTS
# ==============================================================================

def test_normalize_domain_uppercase():
    assert normalize_domain("EXAMPLE.COM") == "example.com"
    assert normalize_domain("Api.Sub.EXAMPLE.COM") == "api.sub.example.com"


def test_normalize_domain_trailing_dot():
    assert normalize_domain("example.com.") == "example.com"
    assert normalize_domain("Example.COM.") == "example.com"
    assert normalize_domain("api.example.com.") == "api.example.com"


def test_normalize_domain_wildcard():
    assert normalize_domain("*.example.com") == "example.com"
    assert normalize_domain("*.Example.COM") == "example.com"
    assert normalize_domain("*.sub.example.com.") == "sub.example.com"
    assert normalize_domain("*example.com") == "example.com"


def test_normalize_domain_subdomain_hierarchy():
    assert normalize_domain("app.staging.v1.example.com") == "app.staging.v1.example.com"
    assert normalize_domain("API.Example.COM") == "api.example.com"


def test_normalize_domain_with_url_or_port_input():
    assert normalize_domain("https://api.example.com:443/v1/test") == "api.example.com"
    assert normalize_domain("example.com:8080") == "example.com"
    assert normalize_domain("user:pass@admin.example.com:443") == "admin.example.com"


def test_normalize_domain_idn_punycode():
    # German umlauts
    assert normalize_domain("münchen.de") == "xn--mnchen-3ya.de"
    assert normalize_domain("MÜNCHEN.DE") == "xn--mnchen-3ya.de"
    assert normalize_domain("bücher.example.com") == "xn--bcher-kva.example.com"
    # Already punycode
    assert normalize_domain("xn--bcher-kva.example.com") == "xn--bcher-kva.example.com"


def test_normalize_domain_malformed_rejected():
    invalid_domains = [
        "",
        "   ",
        None,
        12345,
        "example..com",  # consecutive dots
        ".example.com",  # leading dot
        "-example.com",  # leading hyphen in label
        "example-.com",  # trailing hyphen in label
        "example.com/path with spaces",
        "exam ple.com",
        "example.com;rm -rf",
        "a" * 64 + ".com",  # label > 63 chars
        ("sub." * 70) + "com",  # domain > 253 chars (283 chars)
    ]
    for inv in invalid_domains:
        with pytest.raises(ValueError):
            normalize_domain(inv)  # type: ignore


# ==============================================================================
# 2. IP ADDRESS NORMALIZATION TESTS
# ==============================================================================

def test_normalize_ip_ipv4_valid():
    assert normalize_ip("192.168.1.1") == "192.168.1.1"
    assert normalize_ip("  10.0.0.1  ") == "10.0.0.1"
    assert normalize_ip("192.168.1.1:8080") == "192.168.1.1"


def test_normalize_ip_ipv4_invalid():
    invalid_ips = ["256.0.0.1", "1.2.3", "not-an-ip", "1.2.3.4.5", "192.168.1.-1", ""]
    for inv in invalid_ips:
        with pytest.raises(ValueError):
            normalize_ip(inv)


def test_normalize_ip_ipv6_canonical():
    # Expanded -> compressed canonical lowercase RFC 5952
    assert normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
    assert normalize_ip("2001:DB8:0:0:0:0:0:1") == "2001:db8::1"
    assert normalize_ip("[::1]") == "::1"
    assert normalize_ip("::1") == "::1"
    assert normalize_ip("FE80:0000:0000:0000:0202:B3FF:FE1E:8329") == "fe80::202:b3ff:fe1e:8329"


def test_normalize_ip_ipv6_invalid():
    invalid_ips = ["2001:xyz::1", "1::2::3", ":::1", "2001:db8:::1", ""]
    for inv in invalid_ips:
        with pytest.raises(ValueError):
            normalize_ip(inv)


# ==============================================================================
# 3. QUERY PARAMETER NORMALIZATION TESTS
# ==============================================================================

def test_normalize_query_sorting():
    assert normalize_query("b=2&a=1") == "a=1&b=2"
    assert normalize_query("?z=9&m=5&a=1") == "a=1&m=5&z=9"
    assert normalize_query("c=3;b=2;a=1") == "a=1&b=2&c=3"


def test_normalize_query_duplicate_keys():
    # Duplicate keys sorted by value ascending
    assert normalize_query("tag=red&tag=blue&sort=asc") == "sort=asc&tag=blue&tag=red"
    assert normalize_query("id=2&id=1&id=3") == "id=1&id=2&id=3"


def test_normalize_query_empty_and_special():
    assert normalize_query("") == ""
    assert normalize_query("?") == ""
    assert normalize_query("key=&other=1") == "key=&other=1"
    assert normalize_query("flag") == "flag"
    assert normalize_query("q=hello+world&lang=en") == "lang=en&q=hello+world"


def test_normalize_query_encoding():
    # Avoid double encoding
    assert normalize_query("q=hello%20world&tag=%3Ctest%3E") == "q=hello+world&tag=%3Ctest%3E"


# ==============================================================================
# 4. URL NORMALIZATION TESTS
# ==============================================================================

def test_normalize_url_scheme_and_hostname_casing():
    assert normalize_url("HTTPS://EXAMPLE.COM/a") == "https://example.com/a"
    assert normalize_url("HTTP://Api.Example.COM/v1") == "http://api.example.com/v1"


def test_normalize_url_default_ports():
    # Default ports removed
    assert normalize_url("http://example.com:80/a") == "http://example.com/a"
    assert normalize_url("https://example.com:443/a") == "https://example.com/a"
    assert normalize_url("https://example.com:443") == "https://example.com/"


def test_normalize_url_non_default_ports():
    # Non-default ports preserved
    assert normalize_url("https://example.com:8443/a") == "https://example.com:8443/a"
    assert normalize_url("http://example.com:8080/api") == "http://example.com:8080/api"


def test_normalize_url_userinfo_stripped():
    # Credentials removed from canonical identity
    assert normalize_url("https://user:password@example.com/api") == "https://example.com/api"
    assert normalize_url("http://admin:secret123@example.com:8080/dashboard") == "http://example.com:8080/dashboard"


def test_normalize_url_path_and_slashes():
    # Root default path
    assert normalize_url("https://example.com") == "https://example.com/"
    # Duplicate slashes collapsed
    assert normalize_url("https://example.com//v1///users") == "https://example.com/v1/users"
    # Dot segments resolved
    assert normalize_url("https://example.com/a/b/../c") == "https://example.com/a/c"
    assert normalize_url("https://example.com/a/./b") == "https://example.com/a/b"
    # Trailing slash preserved for non-root paths
    assert normalize_url("https://example.com/api/v1/") == "https://example.com/api/v1/"
    assert normalize_url("https://example.com/api/v1") == "https://example.com/api/v1"


def test_normalize_url_query_parameters():
    assert normalize_url("https://example.com/?b=2&a=1") == "https://example.com/?a=1&b=2"
    assert normalize_url("https://example.com/search?q=test&page=2&page=1") == "https://example.com/search?page=1&page=2&q=test"


def test_normalize_url_fragments_stripped():
    assert normalize_url("https://example.com/page#section-1") == "https://example.com/page"
    assert normalize_url("https://example.com/page?id=1#anchor") == "https://example.com/page?id=1"


def test_normalize_url_ipv6_literal():
    assert normalize_url("https://[2001:0db8::0001]:8443/test") == "https://[2001:db8::1]:8443/test"
    assert normalize_url("https://[::1]:443/api") == "https://[::1]/api"


def test_normalize_url_malformed_rejected():
    invalid_urls = [
        "",
        None,
        "ftp://example.com/file",
        "https://",
        "https://:8080/path",
        "https://example.com:999999/path",  # port out of range
        "https://exam ple.com/path",
    ]
    for inv in invalid_urls:
        with pytest.raises(ValueError):
            normalize_url(inv)  # type: ignore


# ==============================================================================
# 5. ASSET IDENTITY & CLASSIFICATION TESTS
# ==============================================================================

def test_normalize_asset_inference():
    # IP inference
    t, v = normalize_asset("192.168.1.1")
    assert t == AssetType.IP_ADDRESS.value
    assert v == "192.168.1.1"

    t, v = normalize_asset("2001:0db8::1")
    assert t == AssetType.IP_ADDRESS.value
    assert v == "2001:db8::1"

    # URL inference
    t, v = normalize_asset("https://API.Example.com:443/v1")
    assert t == AssetType.URL.value
    assert v == "https://api.example.com/v1"

    # Domain vs Subdomain inference
    t, v = normalize_asset("example.com")
    assert t == AssetType.DOMAIN.value
    assert v == "example.com"

    t, v = normalize_asset("API.EXAMPLE.COM")
    assert t == AssetType.SUBDOMAIN.value
    assert v == "api.example.com"


def test_semantic_equivalence_identity():
    """Two semantically equivalent representations MUST yield the exact same identity."""
    u1 = normalize_url("HTTPS://EXAMPLE.COM:443/api/v1?b=2&a=1#section")
    u2 = normalize_url("https://example.com/api//v1?a=1&b=2")
    assert u1 == u2

    d1 = normalize_domain("*.API.EXAMPLE.COM.")
    d2 = normalize_domain("api.example.com")
    assert d1 == d2


# ==============================================================================
# 6. SECURITY INVARIANTS: ZERO NETWORK / ZERO SUBPROCESS CALLS
# ==============================================================================

def test_security_invariants_zero_network_and_zero_subprocess():
    """Ensure normalizer NEVER calls socket, urllib network, requests, aiohttp, or subprocess."""
    with patch("socket.gethostbyname", side_effect=RuntimeError("NETWORK PROHIBITED")), \
         patch("socket.getaddrinfo", side_effect=RuntimeError("NETWORK PROHIBITED")), \
         patch("subprocess.Popen", side_effect=RuntimeError("SUBPROCESS PROHIBITED")), \
         patch("asyncio.create_subprocess_exec", side_effect=RuntimeError("SUBPROCESS PROHIBITED")):
        
        # Test domain normalization
        assert normalize_domain("*.API.Example.COM.") == "api.example.com"
        assert normalize_domain("MÜNCHEN.DE") == "xn--mnchen-3ya.de"

        # Test IP normalization
        assert normalize_ip("192.168.1.1") == "192.168.1.1"
        assert normalize_ip("2001:0db8::1") == "2001:db8::1"

        # Test URL normalization
        assert normalize_url("HTTPS://user:pass@Example.COM:443/a/../b/?z=1&a=2#frag") == "https://example.com/b/?a=2&z=1"

        # Test Asset normalization
        t, v = normalize_asset("https://API.Example.COM/v1")
        assert t == "URL"
        assert v == "https://api.example.com/v1"
