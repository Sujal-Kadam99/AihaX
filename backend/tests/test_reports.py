import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.models.database import Finding, Scan, User, get_db, init_db, get_engine
from sqlalchemy.orm import sessionmaker
from backend.core.auth import get_current_user
import uuid

@pytest.fixture(autouse=True)
def setup_db(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///")
    import backend.models.database as dbmod
    dbmod._engine = None
    dbmod._SessionLocal = None
    init_db()

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

@pytest.fixture
def mock_user(test_db_session):
    user = User(id=str(uuid.uuid4()), google_sub="report_tester", email="tester@aihax.local")
    test_db_session.add(user)
    test_db_session.commit()
    return user

@pytest.fixture
def api_token():
    from backend.core.auth import get_or_create_api_token
    return get_or_create_api_token()

@pytest.fixture
def client(api_token, mock_user):
    app.dependency_overrides[get_current_user] = lambda: mock_user
    return TestClient(app, headers={"Authorization": f"Bearer {api_token}"})

def test_download_scan_report(test_db_session, client, mock_user):
    scan_id = "test_scan_report_11"
    scan = Scan(id=scan_id, target_url="https://example.com", status="completed", user_id=mock_user.id)
    test_db_session.add(scan)
    
    finding = Finding(
        scan_id=scan_id,
        agent_id=1,
        title="Test Vuln",
        vuln_type="C001_Open_Port_80",
        category="recon",
        severity="high",
        affected_url="https://example.com",
        payload="<script>alert(1)</script>",
        confidence=90,
        verdict="Verified",
        false_positive=False
    )
    test_db_session.add(finding)
    test_db_session.commit()

    # 1. Full Package mode (default)
    response = client.get(f"/api/reports/scan/{scan_id}")
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/pdf"
    assert f"aihax-report-{scan_id[:8]}.pdf" in response.headers["Content-Disposition"]
    assert response.content.startswith(b"%PDF-")

    # 2. Executive report mode
    exec_res = client.get(f"/api/reports/scan/{scan_id}?mode=executive")
    assert exec_res.status_code == 200
    assert exec_res.headers["Content-Type"] == "application/pdf"
    assert exec_res.content.startswith(b"%PDF-")

    # 3. Bug Bounty report mode
    bb_res = client.get(f"/api/reports/scan/{scan_id}?mode=bugbounty")
    assert bb_res.status_code == 200
    assert bb_res.headers["Content-Type"] == "application/pdf"
    assert bb_res.content.startswith(b"%PDF-")

    # 4. Full package explicit mode
    full_res = client.get(f"/api/reports/scan/{scan_id}?mode=full")
    assert full_res.status_code == 200
    assert full_res.headers["Content-Type"] == "application/pdf"
    assert full_res.content.startswith(b"%PDF-")


def test_download_scan_report_not_found(client):
    response = client.get("/api/reports/scan/non_existent_scan")
    assert response.status_code == 404

