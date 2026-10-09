import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.models.database import User, Subscription, Scan, EntitlementCache, get_db, init_db, get_engine
from sqlalchemy.orm import sessionmaker
from backend.core.auth import get_current_user
import uuid
from datetime import datetime, timedelta, timezone

@pytest.fixture(autouse=True)
def setup_test_environment():
    init_db()
    yield

@pytest.fixture
def test_db_session():
    Session = sessionmaker(bind=get_engine())
    db = Session()
    yield db
    db.close()

def override_get_db():
    Session = sessionmaker(bind=get_engine())
    db = Session()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(autouse=True)
def mock_user_context(monkeypatch, mock_user):
    monkeypatch.setattr("backend.core.auth.get_user_context", lambda req: {"user_id": mock_user.id, "email": mock_user.email})

@pytest.fixture
def mock_user(test_db_session, setup_test_environment):
    user = test_db_session.query(User).filter_by(google_sub="entitlement_tester").first()
    if not user:
        user = User(id=str(uuid.uuid4()), google_sub="entitlement_tester", email="tester@aihax.local")
        test_db_session.add(user)
        test_db_session.commit()
    
    # Clear any state from previous tests
    test_db_session.query(Subscription).filter_by(email=user.email).delete()
    test_db_session.query(Scan).filter_by(user_id=user.id).delete()
    test_db_session.query(EntitlementCache).filter_by(user_id=user.id).delete()
    test_db_session.commit()

    return user

@pytest.fixture
def client(mock_user):
    from backend.core.auth import get_or_create_api_token
    api_token = get_or_create_api_token()
    app.dependency_overrides[get_current_user] = lambda: mock_user
    return TestClient(app, headers={"Authorization": f"Bearer {api_token}"})

def test_get_entitlements_free(client):
    response = client.get("/api/billing/entitlements")
    assert response.status_code == 200
    data = response.json()
    assert data["tier"] == "free"
    assert "token" in data
    from backend.core.entitlements import EntitlementManager
    payload = EntitlementManager.verify_entitlement_token(data["token"])
    assert payload["tier"] == "free"

def test_get_entitlements_pro(test_db_session, client, mock_user):
    sub = Subscription(
        email=mock_user.email,
        plan_name="AihaX Pro",
        status="active",
        end_date=datetime.now(timezone.utc) + timedelta(days=30)
    )
    test_db_session.add(sub)
    test_db_session.commit()

    response = client.get("/api/billing/entitlements")
    assert response.status_code == 200
    data = response.json()
    assert data["tier"] == "pro"
    cached = test_db_session.query(EntitlementCache).filter_by(user_id=mock_user.id).one()
    assert cached.entitlement_jwt == data["token"]

def test_expired_active_subscription_does_not_grant_tier(test_db_session, client, mock_user):
    sub = Subscription(
        email=mock_user.email,
        plan_name="AihaX Pro",
        status="active",
        end_date=datetime.now(timezone.utc) - timedelta(days=1)
    )
    test_db_session.add(sub)
    test_db_session.commit()

    response = client.get("/api/billing/entitlements")
    assert response.status_code == 200
    assert response.json()["tier"] == "free"

def test_freemium_scan_limit_blocked(test_db_session, client, mock_user):
    # Free tier by default. Create 3 scans for this user this month.
    for i in range(3):
        scan = Scan(id=str(uuid.uuid4()), target_url="https://example.com", user_id=mock_user.id, user_email=mock_user.email)
        test_db_session.add(scan)
    test_db_session.commit()

    # 4th scan should be blocked
    response = client.post("/api/scan/start", json={"target_url": "https://example.com", "scan_depth": "normal", "scan_mode": "standard"})
    assert response.status_code == 402
    assert "Free tier limit" in response.json()["detail"]

def test_freemium_advanced_features_blocked(client):
    response = client.post("/api/scan/start", json={
        "target_url": "https://example.com", 
        "scan_depth": "deep", 
        "scan_mode": "standard"
    })
    assert response.status_code == 403
    assert "Advanced features" in response.json()["detail"]


def test_local_api_token_and_client_flags_do_not_grant_paid_access(client, monkeypatch):
    monkeypatch.setattr(
        "backend.core.auth.get_user_context",
        lambda req: {"user_id": None, "email": None},
    )
    response = client.post(
        "/api/scan/start",
        json={
            "target_url": "https://example.com",
            "scan_depth": "deep",
            "scan_mode": "standard",
            "admin_mode": True,
            "waf_bypass": True,
        },
    )
    assert response.status_code == 403

def test_tampered_cached_entitlement_falls_back_to_free(client, test_db_session, mock_user):
    response = client.get("/api/billing/entitlements")
    assert response.status_code == 200
    cached = test_db_session.query(EntitlementCache).filter_by(user_id=mock_user.id).one()
    parts = cached.entitlement_jwt.split(".")
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    cached.entitlement_jwt = ".".join(parts)
    test_db_session.commit()

    scan_response = client.post(
        "/api/scan/start",
        json={"target_url": "https://example.com", "scan_depth": "deep", "scan_mode": "standard"},
    )
    assert scan_response.status_code == 403


def test_pro_bypasses_freemium_limits(test_db_session, client, mock_user):
    sub = Subscription(
        email=mock_user.email,
        plan_name="AihaX Pro",
        status="active",
        end_date=datetime.now(timezone.utc) + timedelta(days=30)
    )
    test_db_session.add(sub)
    
    # 3 existing scans
    for i in range(3):
        scan = Scan(id=str(uuid.uuid4()), target_url="https://example.com", user_id=mock_user.id, user_email=mock_user.email)
        test_db_session.add(scan)
    test_db_session.commit()

    # The cloud-issued signed entitlement is cached locally before offline use.
    assert client.get("/api/billing/entitlements").json()["tier"] == "pro"

    # 4th scan allowed because Pro
    response = client.post("/api/scan/start", json={
        "target_url": "https://example.com", 
        "scan_depth": "deep", 
        "scan_mode": "standard"
    })
    # Since they are pro, deep scan is allowed.
    assert response.status_code == 200
    assert response.json()["status"] == "pending"
