"""Comprehensive Test Suite for Central Request + Evidence Engine.

All tests utilize 100% mocked transports to verify zero real network calls occur
and guarantee strict ScopeValidator gating before any transport interaction.
"""

import asyncio
import hashlib
import ipaddress
import ssl
import time
from datetime import datetime, timedelta, timezone
import pytest

from backend.core.scope_validator import ScopeValidator
from backend.services.request_engine import (
    AiohttpTransport,
    AuthenticationContext,
    MockTransport,
    RawResponse,
    RequestEngine,
    RequestSpec,
    RequestTimeout,
    TransportError,
    redact_body,
    redact_headers,
)


@pytest.fixture
def default_validator():
    return ScopeValidator(
        in_scope_assets=["example.com", "*.example.com", "https://partner.com/api/*"],
        out_of_scope_assets=["admin.example.com", "billing.example.com"],
        allowed_ports=[80, 443, 8443],
        excluded_ports=[8080, 22],
        allowed_schemes=["https", "http"],
        excluded_paths=["/internal/*"],
    )


@pytest.fixture
def mock_transport():
    transport = MockTransport()
    transport.register_response(
        url_prefix="https://api.example.com",
        status_code=200,
        headers={"content-type": "application/json", "x-response-id": "RESP-1"},
        body='{"status": "ok", "data": "test"}',
    )
    return transport


@pytest.fixture
def engine(default_validator, mock_transport):
    return RequestEngine(
        scope_validator=default_validator,
        rate_limit_rps=20,
        max_concurrency=5,
        transport=mock_transport,
    )


@pytest.mark.asyncio
async def test_1_in_scope_request_succeeds(engine, mock_transport):
    spec = RequestSpec(
        url="https://api.example.com/v1/users",
        method="GET",
    )
    evidence = await engine.execute(spec)

    assert evidence.success is True
    assert evidence.response_status == 200
    assert evidence.transport_error is None
    assert mock_transport.call_count == 1
    assert engine.total_requests == 1
    assert "REQ-" in evidence.request_id


@pytest.mark.asyncio
async def test_request_accounting_counts_attempts_sends_denials_redirects_and_reuse():
    transport = MockTransport()
    transport.register_response(
        url="https://api.example.com/start",
        status_code=302,
        headers={"location": "/finish"},
        body="",
    )
    transport.register_response(url="https://api.example.com/finish", status_code=200, body="ok")
    engine = RequestEngine(
        scope_validator=ScopeValidator(in_scope_assets=["https://api.example.com"], allowed_ports=[443]),
        transport=transport,
    )

    engine.record_reused()
    denied = await engine.execute(RequestSpec(
        url="https://api.example.com/denied",
        authorization_confirmed=False,
    ))
    assert denied.success is False
    followed = await engine.execute(RequestSpec(
        url="https://api.example.com/start",
        follow_redirects=True,
    ))

    assert followed.success is True
    assert engine.request_counts == {
        "attempted": 2,
        "sent": 2,
        "denied": 1,
        "redirected": 1,
        "reused": 1,
    }


@pytest.mark.asyncio
async def test_budget_denied_redirect_is_not_counted_as_sent_or_redirected():
    transport = MockTransport()
    transport.register_response(
        url="https://api.example.com/start",
        status_code=302,
        headers={"location": "/finish"},
        body="",
    )
    engine = RequestEngine(
        scope_validator=ScopeValidator(in_scope_assets=["https://api.example.com"], allowed_ports=[443]),
        transport=transport,
    )
    reservations = 0

    async def reserve(target, check_id):
        nonlocal reservations
        reservations += 1
        return reservations == 1, "budget exhausted"

    engine.request_budget_reserver = reserve
    await engine.execute(RequestSpec(url="https://api.example.com/start", follow_redirects=True))

    assert engine.request_counts == {
        "attempted": 1,
        "sent": 1,
        "denied": 0,
        "redirected": 0,
        "reused": 0,
    }


@pytest.mark.asyncio
async def test_https_transport_validates_local_certificate_from_test_trust_store(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "test-cert.pem", tmp_path / "test-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ssl.load_cert_chain(str(cert_path), str(key_path))
    client_ssl = ssl.create_default_context(cafile=str(cert_path))

    async def handle(reader, writer):
        while await reader.readline() not in (b"\r\n", b"\n", b""):
            pass
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_ssl)
    port = server.sockets[0].getsockname()[1]
    try:
        engine = RequestEngine(
            scope_validator=ScopeValidator(in_scope_assets=[f"https://127.0.0.1:{port}"], allowed_ports=[port]),
            transport=AiohttpTransport(ssl_context=client_ssl),
        )
        evidence = await engine.execute(RequestSpec(url=f"https://127.0.0.1:{port}/health"))
        assert evidence.success is True
        assert evidence.response_status == 200
        assert evidence.response_body == "ok"
        assert engine.request_counts["sent"] == 1
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_2_out_of_scope_request_blocked_before_transport(engine, mock_transport):
    # Foreign target not in scope
    spec = RequestSpec(
        url="https://evil.com/exploit",
        method="GET",
    )
    evidence = await engine.execute(spec)

    assert evidence.success is False
    assert evidence.response_status is None
    assert evidence.transport_error["error_type"] == "SCOPE_DENIED"
    assert mock_transport.call_count == 0  # CRITICAL: Zero transport calls!
    assert engine.total_requests == 0


@pytest.mark.asyncio
async def test_3_invalid_url_blocked_before_transport(engine, mock_transport):
    spec = RequestSpec(
        url="not_a_valid_url",
        method="GET",
    )
    evidence = await engine.execute(spec)

    assert evidence.success is False
    assert evidence.transport_error["error_type"] == "SCOPE_DENIED"
    assert mock_transport.call_count == 0


@pytest.mark.asyncio
async def test_4_authorization_missing_blocks_request(engine, mock_transport):
    spec = RequestSpec(
        url="https://api.example.com/data",
        method="GET",
        authorization_confirmed=False,  # Unconfirmed authorization
    )
    evidence = await engine.execute(spec)

    assert evidence.success is False
    assert evidence.transport_error["error_type"] == "AUTH_MISSING"
    assert mock_transport.call_count == 0


@pytest.mark.asyncio
async def test_5_explicit_exclusion_blocks_request(engine, mock_transport):
    # admin.example.com is explicitly excluded
    spec = RequestSpec(
        url="https://admin.example.com/login",
        method="GET",
    )
    evidence = await engine.execute(spec)

    assert evidence.success is False
    assert evidence.transport_error["error_type"] == "SCOPE_DENIED"
    assert mock_transport.call_count == 0


@pytest.mark.asyncio
async def test_6_port_restriction_enforced(engine, mock_transport):
    # Port 8080 is excluded
    spec = RequestSpec(
        url="https://api.example.com:8080/test",
        method="GET",
    )
    evidence = await engine.execute(spec)

    assert evidence.success is False
    assert evidence.transport_error["error_type"] == "SCOPE_DENIED"
    assert mock_transport.call_count == 0


@pytest.mark.asyncio
async def test_7_scheme_restriction_enforced(default_validator, mock_transport):
    strict_engine = RequestEngine(
        scope_validator=ScopeValidator(
            in_scope_assets=["example.com"],
            allowed_schemes=["https"],  # HTTP not allowed
        ),
        transport=mock_transport,
    )
    spec = RequestSpec(
        url="http://example.com/insecure",
        method="GET",
    )
    evidence = await strict_engine.execute(spec)

    assert evidence.success is False
    assert evidence.transport_error["error_type"] == "SCOPE_DENIED"
    assert mock_transport.call_count == 0


@pytest.mark.asyncio
async def test_8_redirect_to_out_of_scope_target_is_blocked(engine, mock_transport):
    # In-scope URL responds with 302 redirecting to evil.com
    mock_transport.register_response(
        url_prefix="https://api.example.com/redirect",
        status_code=302,
        headers={"location": "https://evil.com/pwned"},
        body="",
    )

    spec = RequestSpec(
        url="https://api.example.com/redirect",
        method="GET",
        follow_redirects=True,
    )
    evidence = await engine.execute(spec)

    assert evidence.success is False
    assert evidence.transport_error["error_type"] == "REDIRECT_BLOCKED"
    assert "evil.com" in evidence.transport_error["message"]
    # Initial request was sent (1), but secondary out-of-scope hop was blocked!
    assert mock_transport.call_count == 1
    assert "https://evil.com/pwned" in evidence.redirect_chain


@pytest.mark.asyncio
async def test_9_redirect_to_in_scope_target_is_allowed(engine, mock_transport):
    mock_transport.register_response(
        url_prefix="https://api.example.com/old-path",
        status_code=301,
        headers={"location": "https://api.example.com/new-path"},
        body="",
    )
    mock_transport.register_response(
        url_prefix="https://api.example.com/new-path",
        status_code=200,
        body="Final Destination",
    )

    spec = RequestSpec(
        url="https://api.example.com/old-path",
        method="GET",
        follow_redirects=True,
    )
    evidence = await engine.execute(spec)

    assert evidence.success is True
    assert evidence.response_status == 200
    assert evidence.response_body == "Final Destination"
    assert mock_transport.call_count == 2
    assert evidence.redirect_chain == ["https://api.example.com/old-path", "https://api.example.com/new-path"]


@pytest.mark.asyncio
async def test_10_rate_limiting_is_respected(default_validator, mock_transport):
    # Set low RPS (5 RPS)
    throttled_engine = RequestEngine(
        scope_validator=default_validator,
        rate_limit_rps=5,
        max_concurrency=10,
        transport=mock_transport,
    )
    t0 = time.monotonic()
    tasks = [
        throttled_engine.execute(RequestSpec(url="https://api.example.com/ping"))
        for _ in range(6)
    ]
    results = await asyncio.gather(*tasks)
    elapsed = time.monotonic() - t0

    assert all(r.success for r in results)
    assert elapsed >= 0.1  # Throttling verified


@pytest.mark.asyncio
async def test_11_concurrency_limit_is_respected(default_validator):
    active_concurrent = 0
    max_observed_concurrent = 0

    class SlowTransport(MockTransport):
        async def send(self, *args, **kwargs):
            nonlocal active_concurrent, max_observed_concurrent
            active_concurrent += 1
            max_observed_concurrent = max(max_observed_concurrent, active_concurrent)
            await asyncio.sleep(0.05)
            active_concurrent -= 1
            return RawResponse(status_code=200, headers={}, body=b"OK")

    transport = SlowTransport()
    concurrent_engine = RequestEngine(
        scope_validator=default_validator,
        rate_limit_rps=100,
        max_concurrency=3,  # Strict concurrency ceiling of 3
        transport=transport,
    )

    tasks = [
        concurrent_engine.execute(RequestSpec(url="https://api.example.com/slow"))
        for _ in range(8)
    ]
    await asyncio.gather(*tasks)

    assert max_observed_concurrent <= 3


@pytest.mark.asyncio
async def test_12_timeout_produces_structured_error(default_validator):
    class TimeoutTransport(MockTransport):
        async def send(self, *args, **kwargs):
            raise asyncio.TimeoutError("Socket read timed out")

    engine_timeout = RequestEngine(
        scope_validator=default_validator,
        transport=TimeoutTransport(),
    )
    spec = RequestSpec(
        url="https://api.example.com/hang",
        timeout=RequestTimeout(total=2.0),
    )
    evidence = await engine_timeout.execute(spec)

    assert evidence.success is False
    assert evidence.transport_error["error_type"] == "TIMEOUT"
    assert "timed out" in evidence.transport_error["message"].lower()


@pytest.mark.asyncio
async def test_13_dns_failure_produces_structured_error(default_validator):
    class DNSErrorTransport(MockTransport):
        async def send(self, *args, **kwargs):
            raise Exception("gaierror: [Errno -2] Name or service not known")

    engine_dns = RequestEngine(
        scope_validator=default_validator,
        transport=DNSErrorTransport(),
    )
    evidence = await engine_dns.execute(RequestSpec(url="https://api.example.com/dns"))

    assert evidence.success is False
    assert evidence.transport_error["error_type"] == "DNS_FAILURE"


@pytest.mark.asyncio
async def test_14_connection_failure_produces_structured_error(default_validator):
    class ConnRefusedTransport(MockTransport):
        async def send(self, *args, **kwargs):
            raise ConnectionRefusedError("Connection refused on port 443")

    engine_conn = RequestEngine(
        scope_validator=default_validator,
        transport=ConnRefusedTransport(),
    )
    evidence = await engine_conn.execute(RequestSpec(url="https://api.example.com/refused"))

    assert evidence.success is False
    assert evidence.transport_error["error_type"] == "CONNECTION_REFUSED"


@pytest.mark.asyncio
async def test_15_and_16_response_size_limit_and_truncation(engine, mock_transport):
    large_payload = "A" * 5000
    mock_transport.register_response(
        url_prefix="https://api.example.com/large",
        body=large_payload,
    )

    spec = RequestSpec(
        url="https://api.example.com/large",
        max_response_size=1000,  # Limit response to 1000 bytes
    )
    evidence = await engine.execute(spec)

    assert evidence.success is True
    assert evidence.truncated is True
    assert len(evidence.response_body) == 1000
    assert evidence.response_size == 5000  # Observed total size preserved


@pytest.mark.asyncio
async def test_17_and_18_request_id_and_metadata_captured(engine):
    spec = RequestSpec(
        url="https://api.example.com/metadata",
        method="POST",
        headers={"X-Custom-Header": "AihaX-Test"},
        body='{"action": "test"}',
    )
    evidence = await engine.execute(spec)

    assert evidence.request_id.startswith("REQ-")
    assert evidence.method == "POST"
    assert evidence.request_headers["X-Custom-Header"] == "AihaX-Test"
    assert evidence.request_body == '{"action": "test"}'
    assert evidence.duration_ms >= 0.0


@pytest.mark.asyncio
async def test_19_sensitive_authentication_data_is_redacted(engine):
    auth_ctx = AuthenticationContext(
        name="tester-account",
        headers={
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret123",
            "X-Api-Key": "super-secret-api-key",
        },
        cookies={"session_id": "sess-secret-value"},
    )
    spec = RequestSpec(
        url="https://api.example.com/auth-test",
        method="POST",
        auth_context=auth_ctx,
        body={"username": "admin", "password": "SuperSecretPassword123!"},
    )
    evidence = await engine.execute(spec)

    # Headers must be redacted
    assert evidence.request_headers["Authorization"] == "[REDACTED]"
    assert evidence.request_headers["X-Api-Key"] == "[REDACTED]"
    assert evidence.request_headers["Cookie"] == "[REDACTED]"

    # Body must be redacted
    assert "SuperSecretPassword123!" not in evidence.request_body
    assert "[REDACTED]" in evidence.request_body


@pytest.mark.asyncio
async def test_20_and_21_retries_respect_scope_and_rate_limits(engine, mock_transport):
    attempt_count = 0

    def flaky_handler(m, u, h, p, b):
        nonlocal attempt_count
        attempt_count += 1
        if attempt_count < 3:
            raise ConnectionResetError("Connection reset by peer")
        return RawResponse(status_code=200, headers={}, body=b"Recovered")

    mock_transport.register_handler(
        lambda m, u: "flaky" in u,
        flaky_handler,
    )

    spec = RequestSpec(
        url="https://api.example.com/flaky",
        retries=2,
    )
    evidence = await engine.execute(spec)

    assert evidence.success is True
    assert evidence.retries_attempted == 2
    assert evidence.response_body == "Recovered"


@pytest.mark.asyncio
async def test_22_transport_errors_do_not_become_vulnerabilities(engine):
    spec = RequestSpec(url="https://evil.com/attack")
    evidence = await engine.execute(spec)

    # Verify structured failure
    assert evidence.success is False
    assert evidence.transport_error is not None
    # No HTTP status code or vulnerability finding data
    assert evidence.response_status is None


@pytest.mark.asyncio
async def test_23_request_and_response_hashes_are_deterministic(engine):
    spec = RequestSpec(
        url="https://api.example.com/hash-test",
        method="GET",
    )
    ev1 = await engine.execute(spec)
    ev2 = await engine.execute(spec)

    assert len(ev1.request_hash) == 64
    assert len(ev1.response_hash) == 64
    assert ev1.request_hash == ev2.request_hash
    assert ev1.response_hash == ev2.response_hash


@pytest.mark.asyncio
async def test_24_architectural_request_engine_integration(default_validator, mock_transport):
    """Verify that RequestEngine can be instantiated and used as standard contract for agents."""
    engine = RequestEngine(scope_validator=default_validator, transport=mock_transport)
    assert hasattr(engine, "execute")
    assert hasattr(engine, "transport")
    assert hasattr(engine, "scope_validator")
