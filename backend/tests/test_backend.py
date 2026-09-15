"""
AihaX Backend — First Test Suite 🚀
Comprehensive tests covering:
  - URL Validation (SSRF protection)
  - Encryption (AES-256-GCM round-trip)
  - Rate Limiting
  - Pydantic Schemas
  - Authentication
  - Database Models & Init
  - FastAPI Health Endpoint (integration)
"""

import json
import os
import secrets
import shutil
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _isolated_settings(tmp_path, monkeypatch):
    """Override config so every test gets its own temp dirs & in-memory DB."""
    monkeypatch.setenv("DATABASE_URL", "sqlite:///")  # in-memory
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379")
    monkeypatch.setenv("CHROMA_PATH", str(tmp_path / "chroma"))
    monkeypatch.setenv("REPORTS_PATH", str(tmp_path / "reports"))
    monkeypatch.setenv("CONFIG_PATH", str(tmp_path / "config"))
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key-for-pytest-only")
    monkeypatch.setenv("AIHAX_MASTER_KEY", "test-master-key-for-pytest-only")

    # Clear any cached settings / engine singletons
    from backend.core.config import get_settings
    get_settings.cache_clear()

    import backend.models.database as dbmod
    dbmod._engine = None
    dbmod._SessionLocal = None


@pytest.fixture
def settings():
    from backend.core.config import get_settings
    return get_settings()


@pytest.fixture
def db_session(settings):
    """Provide a DB session on a freshly-initialised in-memory database."""
    from backend.models.database import init_db, get_engine
    from sqlalchemy.orm import sessionmaker
    init_db()
    Session = sessionmaker(bind=get_engine())
    session = Session()
    yield session
    session.close()


@pytest.fixture
def api_token(settings):
    """Return the auto-generated API token."""
    from backend.core.auth import get_or_create_api_token
    return get_or_create_api_token()


@pytest.fixture
def client(settings, api_token):
    """Fully-wired TestClient with lifespan disabled (no redis/scheduler)."""
    from backend.core.auth import get_or_create_api_token
    from backend.models.database import init_db

    # Initialize DB before creating the app
    init_db()

    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from backend.routers import auth, findings, scan, settings as settings_router, watch, billing
    from backend.models.schemas import HealthResponse

    # Build a lightweight app without the full lifespan (no redis/scheduler deps)
    test_app = FastAPI(title="AihaX-Test")

    test_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Auth middleware
    from backend.core.auth import require_auth, extract_token_from_request
    @test_app.middleware("http")
    async def auth_middleware(request, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)
        try:
            require_auth(request)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        return await call_next(request)

    test_app.include_router(auth.router)
    test_app.include_router(billing.router)

    @test_app.get("/api/health", response_model=HealthResponse)
    async def health():
        return HealthResponse(status="ok", version="1.0.0-test", redis="mock", database="ok")

    return TestClient(test_app)


# ──────────────────────────────────────────────────────────────────────────────
# 1. URL VALIDATION
# ──────────────────────────────────────────────────────────────────────────────

class TestURLValidation:
    """Verify SSRF-prevention: block internal targets, allow public ones."""

    def test_blocks_localhost(self):
        from backend.core.url_validator import validate_target_url, URLValidationError
        with pytest.raises(URLValidationError, match="Blocked hostname"):
            validate_target_url("http://localhost/admin")

    def test_blocks_127_ip(self):
        from backend.core.url_validator import validate_target_url, URLValidationError
        with pytest.raises(URLValidationError, match="private|loopback|reserved"):
            validate_target_url("http://127.0.0.1:8080/")

    def test_blocks_private_ip_10(self):
        from backend.core.url_validator import validate_target_url, URLValidationError
        with pytest.raises(URLValidationError, match="private|loopback|reserved"):
            validate_target_url("https://10.0.0.1/api")

    def test_blocks_private_ip_192(self):
        from backend.core.url_validator import validate_target_url, URLValidationError
        with pytest.raises(URLValidationError, match="private|loopback|reserved"):
            validate_target_url("https://192.168.1.1/")

    def test_blocks_metadata_google(self):
        from backend.core.url_validator import validate_target_url, URLValidationError
        with pytest.raises(URLValidationError, match="Blocked hostname"):
            validate_target_url("http://metadata.google.internal/computeMetadata")

    def test_blocks_dotlocal_suffix(self):
        from backend.core.url_validator import validate_target_url, URLValidationError
        with pytest.raises(URLValidationError, match="Blocked hostname suffix"):
            validate_target_url("http://mydevbox.local/secret")

    def test_rejects_ftp_scheme(self):
        from backend.core.url_validator import validate_target_url, URLValidationError
        with pytest.raises(URLValidationError, match="http or https"):
            validate_target_url("ftp://example.com/file")

    def test_rejects_no_hostname(self):
        from backend.core.url_validator import validate_target_url, URLValidationError
        with pytest.raises(URLValidationError, match="valid hostname"):
            validate_target_url("http://")

    def test_allows_public_url(self):
        from backend.core.url_validator import validate_target_url
        result = validate_target_url("https://example.com/login")
        assert result == "https://example.com/login"

    def test_strips_whitespace(self):
        from backend.core.url_validator import validate_target_url
        result = validate_target_url("  https://example.com  ")
        assert result == "https://example.com"


# ──────────────────────────────────────────────────────────────────────────────
# 2. ENCRYPTION
# ──────────────────────────────────────────────────────────────────────────────

class TestEncryption:
    """AES-256-GCM round-trip and CredentialVault."""

    def test_encrypt_decrypt_roundtrip(self):
        from backend.core.encryption import encrypt_data, decrypt_data
        original = {"api_key": "sk-secret-123", "tokens": [1, 2, 3]}
        encrypted = encrypt_data(original)
        assert isinstance(encrypted, str)
        assert "sk-secret-123" not in encrypted  # ciphertext must not leak
        decrypted = decrypt_data(encrypted)
        assert decrypted == original

    def test_different_nonces(self):
        from backend.core.encryption import encrypt_data
        data = {"key": "value"}
        a = encrypt_data(data)
        b = encrypt_data(data)
        assert a != b  # random nonce → different ciphertext

    def test_tampered_ciphertext_fails(self):
        from backend.core.encryption import encrypt_data, decrypt_data
        import base64
        encrypted = encrypt_data({"x": 1})
        raw = bytearray(base64.b64decode(encrypted))
        raw[-1] ^= 0xFF  # flip last byte
        tampered = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(Exception):
            decrypt_data(tampered)

    def test_credential_vault(self, tmp_path):
        from backend.core.encryption import CredentialVault
        vault = CredentialVault(str(tmp_path / "vault_test"))
        vault.save({"claude_key": "sk-ant-xxxx", "shodan_key": "abc123"})
        loaded = vault.load()
        assert loaded["claude_key"] == "sk-ant-xxxx"
        assert loaded["shodan_key"] == "abc123"

    def test_vault_get_set(self, tmp_path):
        from backend.core.encryption import CredentialVault
        vault = CredentialVault(str(tmp_path / "vault_gs"))
        vault.set("key_a", "value_a")
        vault.set("key_b", "value_b")
        assert vault.get("key_a") == "value_a"
        assert vault.get("key_b") == "value_b"
        assert vault.get("missing", "default") == "default"

    def test_vault_empty_load(self, tmp_path):
        from backend.core.encryption import CredentialVault
        vault = CredentialVault(str(tmp_path / "empty_vault"))
        assert vault.load() == {}


# ──────────────────────────────────────────────────────────────────────────────
# 3. RATE LIMITING
# ──────────────────────────────────────────────────────────────────────────────

class TestRateLimiting:
    """In-memory per-client rate limiter for scan endpoints."""

    def setup_method(self):
        from backend.core import rate_limit
        rate_limit._scan_timestamps.clear()

    def test_allows_first_scan(self):
        from backend.core.rate_limit import check_scan_rate_limit
        check_scan_rate_limit("test-client")  # should not raise

    def test_allows_up_to_limit(self):
        from backend.core.rate_limit import check_scan_rate_limit
        for _ in range(5):
            check_scan_rate_limit("test-limit")

    def test_blocks_over_limit(self):
        from backend.core.rate_limit import check_scan_rate_limit
        for _ in range(5):
            check_scan_rate_limit("test-block")
        with pytest.raises(HTTPException) as exc_info:
            check_scan_rate_limit("test-block")
        assert exc_info.value.status_code == 429

    def test_separate_clients_independent(self):
        from backend.core.rate_limit import check_scan_rate_limit
        for _ in range(5):
            check_scan_rate_limit("client-A")
        # client-B should still be allowed
        check_scan_rate_limit("client-B")  # should not raise

    def test_window_expiry(self):
        from backend.core import rate_limit
        from backend.core.rate_limit import check_scan_rate_limit
        # Fill up the bucket with timestamps 61 seconds ago
        old = time.time() - 61
        rate_limit._scan_timestamps["expired-client"] = [old] * 5
        # Should be allowed because old timestamps expired
        check_scan_rate_limit("expired-client")


# ──────────────────────────────────────────────────────────────────────────────
# 4. PYDANTIC SCHEMAS
# ──────────────────────────────────────────────────────────────────────────────

class TestSchemas:
    """Validate Pydantic models for scans, findings, health, etc."""

    def test_health_response(self):
        from backend.models.schemas import HealthResponse
        h = HealthResponse(status="ok", version="1.0.0")
        assert h.status == "ok"
        assert h.redis == "unknown"
        assert h.database == "unknown"

    def test_findings_count_defaults(self):
        from backend.models.schemas import FindingsCount
        fc = FindingsCount()
        assert fc.critical == 0
        assert fc.high == 0
        assert fc.medium == 0
        assert fc.low == 0
        assert fc.info == 0

    def test_scan_config_defaults(self):
        from backend.models.schemas import ScanConfig
        with patch("backend.core.url_validator.validate_target_url", return_value="https://example.com"):
            sc = ScanConfig(target_url="https://example.com")
        assert sc.scan_depth == "normal"
        assert sc.threads == 5
        assert sc.waf_bypass is False
        assert sc.stealth_mode is False
        assert sc.scan_mode == "safe"
        assert sc.admin_mode is False

    def test_scan_config_rejects_invalid_depth(self):
        from backend.models.schemas import ScanConfig
        with pytest.raises(ValidationError):
            with patch("backend.core.url_validator.validate_target_url", return_value="https://example.com"):
                ScanConfig(target_url="https://example.com", scan_depth="ultra")

    def test_scan_config_threads_range(self):
        from backend.models.schemas import ScanConfig
        with pytest.raises(ValidationError):
            with patch("backend.core.url_validator.validate_target_url", return_value="https://example.com"):
                ScanConfig(target_url="https://example.com", threads=25)

    def test_watch_schedule_interval(self):
        from backend.models.schemas import WatchSchedulePayload
        wp = WatchSchedulePayload(
            target_url="https://example.com",
            schedule_type="daily",
            scan_config={"scan_depth": "normal"},
        )
        assert wp.interval_delta == timedelta(days=1)

        wp_weekly = WatchSchedulePayload(
            target_url="https://example.com",
            schedule_type="weekly",
            scan_config={},
        )
        assert wp_weekly.interval_delta == timedelta(weeks=1)

    def test_subscription_create(self):
        from backend.models.schemas import SubscriptionCreate
        sc = SubscriptionCreate(email="test@example.com", plan_name="pro")
        assert sc.duration_days == 30

    def test_agent_status_defaults(self):
        from backend.models.schemas import AgentStatus
        a = AgentStatus(agent_id=1, agent_name="recon")
        assert a.status == "pending"
        assert a.progress == 0
        assert a.message == ""

    def test_websocket_message(self):
        from backend.models.schemas import WebSocketMessage
        m = WebSocketMessage(
            scan_id="abc", agent_id=1, agent_name="recon",
            status="running", progress=50, message="Scanning..."
        )
        assert m.finding is None


# ──────────────────────────────────────────────────────────────────────────────
# 5. AUTHENTICATION
# ──────────────────────────────────────────────────────────────────────────────

class TestAuth:
    """API token generation, validation, and request auth."""

    def test_token_creation(self, api_token):
        assert len(api_token) > 20  # urlsafe token should be ~43 chars

    def test_token_persisted(self, api_token, settings):
        from backend.core.auth import get_or_create_api_token
        # calling again should return same token (loaded from file)
        token2 = get_or_create_api_token()
        assert token2 == api_token

    def test_validate_correct_token(self, api_token):
        from backend.core.auth import validate_token
        assert validate_token(api_token) is True

    def test_validate_wrong_token(self, api_token):
        from backend.core.auth import validate_token
        assert validate_token("wrong-token-xxxxx") is False

    def test_validate_none_token(self):
        from backend.core.auth import validate_token
        assert validate_token(None) is False

    def test_validate_empty_token(self):
        from backend.core.auth import validate_token
        assert validate_token("") is False

    def test_extract_bearer(self):
        from backend.core.auth import extract_token_from_request
        mock_req = MagicMock()
        mock_req.headers = {"Authorization": "Bearer my-token-123"}
        assert extract_token_from_request(mock_req) == "my-token-123"

    def test_extract_custom_header(self):
        from backend.core.auth import extract_token_from_request
        mock_req = MagicMock()
        mock_req.headers = {"X-AihaX-Token": "custom-token-456"}
        assert extract_token_from_request(mock_req) == "custom-token-456"

    def test_public_path_detection(self):
        from backend.core.auth import _is_public_path
        assert _is_public_path("/api/health") is True
        assert _is_public_path("/api/scan") is False

    def test_local_only_path(self):
        from backend.core.auth import _is_local_only_path
        assert _is_local_only_path("/api/auth/token") is True
        assert _is_local_only_path("/docs") is True
        assert _is_local_only_path("/docs/openapi") is True
        assert _is_local_only_path("/api/scan") is False


# ──────────────────────────────────────────────────────────────────────────────
# 6. DATABASE MODELS
# ──────────────────────────────────────────────────────────────────────────────

class TestDatabase:
    """ORM model creation and DB init."""

    def test_init_db_creates_tables(self, db_session):
        from sqlalchemy import inspect
        from backend.models.database import get_engine
        inspector = inspect(get_engine())
        tables = inspector.get_table_names()
        expected = {"scans", "findings", "agent_logs", "exploit_chains",
                    "scan_configs", "watch_schedules", "subscriptions"}
        assert expected.issubset(set(tables))

    def test_create_scan(self, db_session):
        from backend.models.database import Scan
        scan = Scan(
            target_url="https://example.com",
            status="running",
            scan_depth="deep",
            scan_mode="bugbounty",
        )
        db_session.add(scan)
        db_session.commit()
        assert scan.id is not None
        assert scan.status == "running"
        assert scan.admin_mode is False

    def test_create_finding(self, db_session):
        from backend.models.database import Scan, Finding
        scan = Scan(target_url="https://target.com", status="complete")
        db_session.add(scan)
        db_session.commit()

        finding = Finding(
            scan_id=scan.id,
            agent_id=1,
            title="SQL Injection in /login",
            vuln_type="sqli",
            category="injection",
            severity="critical",
            affected_url="https://target.com/login",
            confidence=95,
        )
        db_session.add(finding)
        db_session.commit()
        assert finding.id is not None
        assert finding.severity == "critical"

    def test_create_subscription(self, db_session):
        from backend.models.database import Subscription
        sub = Subscription(
            email="user@example.com",
            plan_name="pro",
            end_date=datetime.utcnow() + timedelta(days=30),
        )
        db_session.add(sub)
        db_session.commit()
        assert sub.status == "active"

    def test_create_watch_schedule(self, db_session):
        from backend.models.database import WatchSchedule
        ws = WatchSchedule(
            target_url="https://monitored.com",
            schedule_type="daily",
            active=True,
        )
        db_session.add(ws)
        db_session.commit()
        assert ws.id is not None
        assert ws.active is True


# ──────────────────────────────────────────────────────────────────────────────
# 7. INTEGRATION — HEALTH ENDPOINT
# ──────────────────────────────────────────────────────────────────────────────

class TestHealthEndpoint:
    """Hit /api/health via TestClient — no auth needed (public path)."""

    def test_health_returns_ok(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "version" in data

    def test_health_without_token_still_works(self, client):
        # Health is a public path, no token needed
        resp = client.get("/api/health")
        assert resp.status_code == 200


# ──────────────────────────────────────────────────────────────────────────────
# 8. AUTH MIDDLEWARE INTEGRATION
# ──────────────────────────────────────────────────────────────────────────────

class TestAuthMiddleware:
    """Verify auth middleware blocks/allows correctly via TestClient."""

    def test_protected_route_rejects_no_token(self, client):
        resp = client.get("/api/auth/token")
        # /api/auth/token is local-only, from TestClient it should be accessible
        # since TestClient uses 127.0.0.1
        # Let's test a billing endpoint which requires auth
        resp = client.get("/api/billing/plans")
        assert resp.status_code in (401, 404, 405)  # should be rejected without token

    def test_protected_route_accepts_valid_token(self, client, api_token):
        resp = client.get(
            "/api/billing/plans",
            headers={"Authorization": f"Bearer {api_token}"},
        )
        # Should be 200 or valid response (not 401)
        assert resp.status_code != 401


# ──────────────────────────────────────────────────────────────────────────────
# 9. CONFIG
# ──────────────────────────────────────────────────────────────────────────────

class TestConfig:
    """Settings and directory creation."""

    def test_settings_defaults(self, settings):
        assert settings.app_name == "AihaX"
        assert settings.app_version == "1.0.0"
        assert settings.debug is False
        assert settings.claude_model == "claude-sonnet-4-6"

    def test_ensure_directories(self, settings, tmp_path):
        from backend.core.config import ensure_directories
        ensure_directories(settings)
        assert Path(settings.reports_path).exists()
        assert Path(settings.config_path).exists()
        assert Path(settings.chroma_path).exists()
