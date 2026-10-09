"""Team workspace membership, seat, and role enforcement tests."""

from datetime import datetime, timedelta, timezone
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.core.auth import get_current_user, get_current_user_optional, get_or_create_api_token
from backend.core.entitlements import EntitlementManager, get_user_tier
from backend.main import app
from backend.models.database import Base, EntitlementCache, OrganizationMember, Subscription, User, get_db
from backend.persistence.models import Campaign


@pytest.fixture
def workspace_api():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, expire_on_commit=False)

    def override_get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    owner = User(
        id="workspace-owner",
        google_sub="workspace-owner-google",
        email="owner@workspace.test",
        account_status="active",
    )
    member = User(
        id="workspace-member",
        google_sub="workspace-member-google",
        email="member@workspace.test",
        account_status="active",
    )
    viewer = User(
        id="workspace-viewer",
        google_sub="workspace-viewer-google",
        email="viewer@workspace.test",
        account_status="active",
    )
    with SessionLocal() as db:
        db.add_all([owner, member, viewer])
        db.add(
            Subscription(
                email=owner.email,
                plan_name="Team",
                status="active",
                end_date=datetime.now(timezone.utc) + timedelta(days=30),
            )
        )
        db.commit()
        token = EntitlementManager.generate_entitlement_token(db, owner)
        claims = EntitlementManager.verify_entitlement_token(token, expected_user_id=owner.id)
        EntitlementManager.cache_entitlement(db, token, claims)

    active_user = {"user": owner}
    app.dependency_overrides[get_current_user] = lambda: active_user["user"]
    app.dependency_overrides[get_current_user_optional] = lambda: active_user["user"]
    app.dependency_overrides[get_user_tier] = lambda: "team"
    client = TestClient(
        app,
        headers={"Authorization": f"Bearer {get_or_create_api_token()}"},
    )
    try:
        yield SessionLocal, client, active_user, owner, member, viewer
    finally:
        client.close()
        for dependency in (get_db, get_current_user, get_current_user_optional, get_user_tier):
            app.dependency_overrides.pop(dependency, None)
        engine.dispose()


def _create_workspace(client) -> str:
    response = client.post("/api/organizations", json={"name": "Security Team"})
    assert response.status_code == 201, response.text
    return response.json()["data"]["id"]


def test_workspace_creator_becomes_owner_and_can_add_existing_account(workspace_api):
    sessions, client, _, _, member, _ = workspace_api
    organization_id = _create_workspace(client)
    response = client.post(
        f"/api/organizations/{organization_id}/members",
        json={"email": member.email, "role": "member"},
    )
    assert response.status_code == 201, response.text
    assert response.json()["data"]["user_id"] == member.id

    with sessions() as db:
        members = db.query(OrganizationMember).filter_by(organization_id=organization_id).all()
        assert {item.role for item in members} == {"owner", "member"}


def test_viewer_can_read_but_cannot_change_campaigns(workspace_api):
    sessions, client, active_user, owner, _, viewer = workspace_api
    organization_id = _create_workspace(client)
    with sessions() as db:
        db.add(
            OrganizationMember(
                organization_id=organization_id,
                user_id=viewer.id,
                role="viewer",
                invited_by_user_id=owner.id,
            )
        )
        campaign = Campaign(
            id=str(uuid.uuid4()),
            name="Shared assessment",
            target_url="https://authorized.example",
            mode="SAFE_SCAN",
            status="DRAFT",
            user_id=owner.id,
            organization_id=organization_id,
            created_at=datetime.now(timezone.utc),
        )
        db.add(campaign)
        db.commit()
        campaign_id = campaign.id

    active_user["user"] = viewer
    read_response = client.get(f"/api/campaigns/{campaign_id}")
    write_response = client.post(f"/api/campaigns/{campaign_id}/pause")
    assert read_response.status_code == 200
    assert write_response.status_code == 403


def test_nonmember_cannot_read_a_workspace_campaign(workspace_api):
    sessions, client, active_user, owner, _, _ = workspace_api
    organization_id = _create_workspace(client)
    with sessions() as db:
        campaign = Campaign(
            id=str(uuid.uuid4()),
            name="Private team assessment",
            target_url="https://authorized.example",
            mode="SAFE_SCAN",
            status="DRAFT",
            user_id=owner.id,
            organization_id=organization_id,
            created_at=datetime.now(timezone.utc),
        )
        db.add(campaign)
        db.commit()
        campaign_id = campaign.id

    outsider = User(
        id="workspace-outsider",
        google_sub="workspace-outsider-google",
        email="outsider@workspace.test",
        account_status="active",
    )
    active_user["user"] = outsider
    response = client.get(f"/api/campaigns/{campaign_id}")
    assert response.status_code == 404


def test_team_plan_enforces_five_member_seat_limit(workspace_api):
    _, client, _, _, member, viewer = workspace_api
    organization_id = _create_workspace(client)
    for target_email in (member.email, viewer.email):
        response = client.post(
            f"/api/organizations/{organization_id}/members",
            json={"email": target_email, "role": "member"},
        )
        assert response.status_code == 201, response.text

    # Create two additional registered accounts to fill the five-seat plan.
    sessions = workspace_api[0]
    extra_users = []
    with sessions() as db:
        for index in range(3):
            user = User(
                id=f"workspace-extra-{index}",
                google_sub=f"workspace-extra-google-{index}",
                email=f"extra{index}@workspace.test",
                account_status="active",
            )
            db.add(user)
            extra_users.append(user.email)
        db.commit()

    for target_email in extra_users[:2]:
        response = client.post(
            f"/api/organizations/{organization_id}/members",
            json={"email": target_email, "role": "viewer"},
        )
        assert response.status_code == 201, response.text

    over_limit = client.post(
        f"/api/organizations/{organization_id}/members",
        json={"email": "extra2@workspace.test", "role": "member"},
    )
    assert over_limit.status_code == 409
