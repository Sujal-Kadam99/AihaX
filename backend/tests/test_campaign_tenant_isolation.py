"""API regression tests for per-account campaign isolation."""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.core.auth import get_current_user_optional, get_or_create_api_token
from backend.main import app
from backend.models.database import Base, get_db
from backend.persistence.models import Campaign


@pytest.fixture
def isolated_api():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    token = get_or_create_api_token()
    client = TestClient(app, headers={"Authorization": f"Bearer {token}"})
    try:
        yield SessionLocal, client
    finally:
        client.close()
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(get_current_user_optional, None)
        engine.dispose()


def _campaign(session_factory, campaign_id: str, owner_id: str | None) -> None:
    with session_factory() as db:
        db.add(
            Campaign(
                id=campaign_id,
                name=campaign_id,
                target_url="https://authorized.example",
                mode="SAFE_SCAN",
                status="DRAFT",
                user_id=owner_id,
                created_at=datetime.now(timezone.utc),
            )
        )
        db.commit()


def test_campaign_detail_is_hidden_from_another_account(isolated_api):
    sessions, client = isolated_api
    _campaign(sessions, "owned-by-a", "user-a")
    app.dependency_overrides[get_current_user_optional] = lambda: SimpleNamespace(
        id="user-b", email="b@example.test"
    )

    response = client.get("/api/campaigns/owned-by-a")
    assert response.status_code == 404


def test_campaign_owner_can_read_their_campaign(isolated_api):
    sessions, client = isolated_api
    _campaign(sessions, "owned-by-a", "user-a")
    app.dependency_overrides[get_current_user_optional] = lambda: SimpleNamespace(
        id="user-a", email="a@example.test"
    )

    response = client.get("/api/campaigns/owned-by-a")
    assert response.status_code == 200
    assert response.json()["data"]["campaign_id"] == "owned-by-a"


def test_local_ipc_cannot_read_an_account_owned_campaign(isolated_api):
    sessions, client = isolated_api
    _campaign(sessions, "owned-by-a", "user-a")
    app.dependency_overrides[get_current_user_optional] = lambda: None

    response = client.get("/api/campaigns/owned-by-a")
    assert response.status_code == 404


def test_campaign_list_is_scoped_to_authenticated_user(isolated_api):
    sessions, client = isolated_api
    _campaign(sessions, "owned-by-a", "user-a")
    _campaign(sessions, "owned-by-b", "user-b")
    app.dependency_overrides[get_current_user_optional] = lambda: SimpleNamespace(
        id="user-a", email="a@example.test"
    )

    response = client.get("/api/campaigns")
    assert response.status_code == 200
    campaign_ids = {item["campaign_id"] for item in response.json()["data"]}
    assert campaign_ids == {"owned-by-a"}


def test_legacy_unowned_campaigns_are_visible_only_to_local_ipc(isolated_api):
    sessions, client = isolated_api
    _campaign(sessions, "legacy-local", None)
    app.dependency_overrides[get_current_user_optional] = lambda: None

    response = client.get("/api/campaigns/legacy-local")
    assert response.status_code == 200
