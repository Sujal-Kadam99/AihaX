"""Tests for Bug Bounty Program and Scope Management APIs."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.main import app
from backend.models.database import Base, get_db
from backend.models.migrations import run_migrations


@pytest.fixture(name="db_session")
def fixture_db_session(tmp_path):
    db_file = tmp_path / "test_programs.db"
    db_url = f"sqlite:///{db_file}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    run_migrations(engine, str(db_file))

    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(name="client")
def fixture_client(db_session):
    from backend.core.auth import get_or_create_api_token

    api_token = get_or_create_api_token()

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, base_url="http://localhost:8000", headers={"Authorization": f"Bearer {api_token}"}) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_create_program_and_scope(client: TestClient):
    payload = {
        "name": "Acme Bug Bounty",
        "description": "Public Bug Bounty Program for Acme Corp",
        "scope": {
            "in_scope_assets": ["*.acme.com", "acme.com", "https://api.partner.com/v1/*"],
            "out_of_scope_assets": ["admin.acme.com", "billing.acme.com"],
            "allowed_ports": [80, 443, 8443],
            "excluded_ports": [22, 3389],
            "allowed_schemes": ["https"],
            "excluded_paths": ["/internal/*"],
            "scope_notes": "Testing permitted only during business hours",
        },
    }

    res = client.post("/api/programs", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["name"] == "Acme Bug Bounty"
    assert data["scope"]["in_scope_assets"] == ["*.acme.com", "acme.com", "https://api.partner.com/v1/*"]
    assert data["scope"]["out_of_scope_assets"] == ["admin.acme.com", "billing.acme.com"]
    assert data["scope"]["allowed_ports"] == [80, 443, 8443]
    assert data["scope"]["excluded_paths"] == ["/internal/*"]

    program_id = data["id"]

    # Test get program
    get_res = client.get(f"/api/programs/{program_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == program_id

    # Test list programs
    list_res = client.get("/api/programs")
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1


def test_validate_target_endpoint(client: TestClient):
    # 1. Create Program
    prog_payload = {
        "name": "Security Program",
        "scope": {
            "in_scope_assets": ["*.example.com", "example.com"],
            "out_of_scope_assets": ["admin.example.com"],
            "allowed_ports": [80, 443],
            "excluded_ports": [8080],
            "allowed_schemes": ["https"],
            "excluded_paths": ["/admin/*"],
        },
    }
    create_res = client.post("/api/programs", json=prog_payload)
    program_id = create_res.json()["id"]

    # 2. Validate in-scope asset
    val1 = client.post(
        f"/api/programs/{program_id}/validate-target",
        json={"target": "https://api.example.com/users"},
    )
    assert val1.status_code == 200
    assert val1.json()["allowed"] is True
    assert val1.json()["status"] == "IN_SCOPE"

    # 3. Validate out-of-scope asset (explicit exclusion)
    val2 = client.post(
        f"/api/programs/{program_id}/validate-target",
        json={"target": "https://admin.example.com/login"},
    )
    assert val2.status_code == 200
    assert val2.json()["allowed"] is False
    assert val2.json()["status"] == "OUT_OF_SCOPE"

    # 4. Validate malicious similar domain (wildcard spoof)
    val3 = client.post(
        f"/api/programs/{program_id}/validate-target",
        json={"target": "https://example.com.evil.com"},
    )
    assert val3.status_code == 200
    assert val3.json()["allowed"] is False
    assert val3.json()["status"] == "DENIED_BY_DEFAULT"

    # 5. Validate port restriction
    val4 = client.post(
        f"/api/programs/{program_id}/validate-target",
        json={"target": "api.example.com", "port": 8080},
    )
    assert val4.status_code == 200
    assert val4.json()["allowed"] is False
    assert val4.json()["status"] == "OUT_OF_SCOPE"


def test_start_scan_with_program_scope_enforcement(client: TestClient, monkeypatch):
    # Mock DNS resolution in validate_target_url so offline/fake domains don't fail DNS
    monkeypatch.setattr("backend.core.url_validator.socket.getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 0))])

    # 1. Create Program
    prog = client.post(
        "/api/programs",
        json={
            "name": "Restricted Target Program",
            "scope": {
                "in_scope_assets": ["*.target.com"],
                "out_of_scope_assets": ["secret.target.com"],
            },
        },
    ).json()
    program_id = prog["id"]

    # 2. Start scan with out-of-scope target -> 400 Bad Request
    bad_scan_payload = {
        "target_url": "https://secret.target.com/api",
        "program_id": program_id,
        "authorization_confirmed": True,
        "scope_notes": "Authorized scope notes",
        "scan_mode": "safe",
    }
    bad_res = client.post("/api/scan/start", json=bad_scan_payload)
    assert bad_res.status_code == 400
    assert "not in authorized program scope" in bad_res.json()["detail"]
