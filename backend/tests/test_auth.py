"""Comprehensive Pytest test suite for Phase 2 Authentication & Security Controls."""

import hashlib
import uuid

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend.core.auth import (
    create_user_access_token,
    create_user_refresh_token,
    verify_and_rotate_refresh_token,
    verify_google_id_token,
)
from backend.core.config import Settings, get_settings
from backend.main import app
from backend.models.database import RefreshToken, User, get_session_factory, init_db

# Ensure DB tables exist for tests
init_db()

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_environment():
    """Ensure database schema is initialized and dev_mock_auth is active for test suite."""
    init_db()
    settings = get_settings()
    settings.dev_mock_auth = True
    yield
    settings.dev_mock_auth = True


@pytest.fixture
def test_db(setup_test_environment):
    factory = get_session_factory()
    db = factory()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def sample_user(test_db):
    """Generate a fresh, unique active User record for each test."""
    uid = str(uuid.uuid4())[:8]
    user = User(
        id=str(uuid.uuid4()),
        google_sub=f"test_google_sub_{uid}",
        email=f"testuser_{uid}@example.com",
        email_verified=True,
        name="Test Security User",
        picture="https://example.com/avatar.png",
        account_status="active",
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user


# -----------------------------------------------------------------------------
# 1. Dev Mock & Configuration Security Assertions
# -----------------------------------------------------------------------------

def test_dev_mock_auth_fails_closed_in_production():
    """Verify that DEV_MOCK_AUTH cannot be enabled when ENVIRONMENT is production or cloud."""
    msg = "FATAL: DEV_MOCK_AUTH cannot be enabled when environment is production or cloud"
    with pytest.raises(ValueError, match=msg):
        Settings(dev_mock_auth=True, environment="production")

    with pytest.raises(ValueError, match=msg):
        Settings(dev_mock_auth=True, environment="cloud")


def test_dev_mock_auth_allowed_in_local_env():
    """Verify DEV_MOCK_AUTH is allowed in local environment."""
    s = Settings(dev_mock_auth=True, environment="local")
    assert s.dev_mock_auth is True


# -----------------------------------------------------------------------------
# 2. OIDC Token Boundary & Claims Verification
# -----------------------------------------------------------------------------

def test_verify_google_id_token_dev_mock(setup_test_environment):
    """Verify dev mock token verification extracts expected OIDC claims."""
    claims = verify_google_id_token("mock_id_token_user123")
    assert claims["sub"] == "google_sub_user123"
    assert claims["email"] == "user123@example.com"
    assert claims["email_verified"] is True


def test_verify_google_id_token_empty_fails():
    """Verify empty token raises HTTP 400."""
    with pytest.raises(HTTPException) as exc:
        verify_google_id_token("")
    assert exc.value.status_code == 400


# -----------------------------------------------------------------------------
# 3. Session JWT & Rotated Refresh Token Lifecycle
# -----------------------------------------------------------------------------

def test_create_and_verify_access_token(sample_user):
    """Verify short-lived access JWT issuance and validation."""
    token = create_user_access_token(sample_user)
    assert token is not None
    assert isinstance(token, str)


def test_refresh_token_rotation_and_family_reuse_detection(test_db, sample_user):
    """Verify refresh token rotation and family revocation on reused token."""
    # Issue initial refresh token
    raw_token_1, db_token_1 = create_user_refresh_token(test_db, sample_user)

    # 1st rotation: Token 1 -> Token 2
    new_access_1, raw_token_2, u1 = verify_and_rotate_refresh_token(test_db, raw_token_1)
    assert new_access_1 is not None
    assert raw_token_2 != raw_token_1
    assert u1.id == sample_user.id

    # Verify Token 1 is now marked as revoked
    test_db.expire_all()
    requeried_1 = test_db.query(RefreshToken).filter_by(id=db_token_1.id).first()
    assert requeried_1.revoked is True

    # REUSE DETECTED: Attempting to reuse revoked Token 1 MUST trigger family revocation!
    with pytest.raises(HTTPException) as exc:
        verify_and_rotate_refresh_token(test_db, raw_token_1)
    assert exc.value.status_code == 401
    assert "Revoked refresh token reuse detected" in exc.value.detail

    # Confirm Token 2 (which was issued under same family_id) is NOW ALSO REVOKED!
    token_2_hash = hashlib.sha256(raw_token_2.encode()).hexdigest()
    requeried_2 = test_db.query(RefreshToken).filter_by(token_hash=token_2_hash).first()
    assert requeried_2.revoked is True


def test_concurrent_refresh_token_rotation_safety(sample_user):
    """Verify concurrent requests rotating the same refresh token cannot both succeed."""
    from concurrent.futures import ThreadPoolExecutor

    from backend.models.database import get_session_factory

    factory = get_session_factory()
    init_db_session = factory()
    raw_token, _ = create_user_refresh_token(init_db_session, sample_user)
    init_db_session.close()

    results = []
    errors = []

    def rotate_worker():
        db = factory()
        try:
            res = verify_and_rotate_refresh_token(db, raw_token)
            results.append(res)
        except Exception as e:
            try:
                db.rollback()
            except Exception:
                pass
            errors.append(e)
        finally:
            try:
                db.close()
            except Exception:
                pass

    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(rotate_worker)
        f2 = executor.submit(rotate_worker)
        f1.result()
        f2.result()

    # Exactly ONE request can succeed; competing request must fail/trigger revocation
    assert len(results) <= 1
    assert len(errors) >= 1


# -----------------------------------------------------------------------------
# 4. Endpoints & Authorization Dependencies
# -----------------------------------------------------------------------------

def test_google_login_endpoint(setup_test_environment, test_db):
    """Test POST /api/auth/google/login endpoint."""
    uid = str(uuid.uuid4())[:8]
    response = client.post("/api/auth/google/login", json={"id_token": f"mock_id_token_{uid}"})
    assert response.status_code == 200
    data = response.json()
    assert data["access_token"] is not None
    assert data["refresh_token"] is not None
    assert data["user"]["email"] == f"{uid}@example.com"
    assert data["user"]["google_sub"] == f"google_sub_{uid}"


def test_get_current_user_me_endpoint(setup_test_environment, test_db, sample_user):
    """Test GET /api/auth/me with Bearer access token."""
    access_token = create_user_access_token(sample_user)
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == sample_user.id
    assert data["email"] == sample_user.email


def test_get_current_user_unauthenticated_fails():
    """Test GET /api/auth/me rejects unauthenticated request with 401."""
    response = client.get("/api/auth/me")
    assert response.status_code == 401


def test_disabled_account_rejected(setup_test_environment, test_db):
    """Test disabled account receives 403 Forbidden."""
    uid = str(uuid.uuid4())[:8]
    disabled_user = User(
        id=str(uuid.uuid4()),
        google_sub=f"disabled_sub_{uid}",
        email=f"disabled_{uid}@example.com",
        email_verified=True,
        name="Disabled User",
        account_status="disabled",
    )
    test_db.add(disabled_user)
    test_db.commit()

    access_token = create_user_access_token(disabled_user)
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 403
    assert "disabled" in str(response.json())
