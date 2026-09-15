import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.models.database import Finding, Scan, get_db, init_db, get_engine
from sqlalchemy.orm import sessionmaker

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
def api_token():
    from backend.core.auth import get_or_create_api_token
    return get_or_create_api_token()

@pytest.fixture
def client(api_token):
    return TestClient(app, headers={"Authorization": f"Bearer {api_token}"})

def test_get_findings_mapping(test_db_session, client):
    # Setup
    scan = Scan(id="test_scan_10", target_url="https://example.com")
    test_db_session.add(scan)
    
    finding = Finding(
        scan_id="test_scan_10",
        agent_id=1,
        title="Test Vuln",
        vuln_type="test",
        category="test_cat",
        severity="high",
        affected_url="https://example.com",
        payload="<script>alert(1)</script>",
        proof_response="HTTP 200 OK alert(1)",
        confidence=90,
        verdict="Verified",
        false_positive=False
    )
    test_db_session.add(finding)
    test_db_session.commit()

    response = client.get("/api/findings/test_scan_10")
        
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    
    f = data[0]
    assert f["verdict"] == "Verified"
    assert f["proof_response"] == "HTTP 200 OK alert(1)"
    assert f["payload"] == "<script>alert(1)</script>"
    assert f["false_positive"] is False


def test_get_finding_detail(test_db_session, client):
    # Setup
    scan = Scan(id="test_scan_11", target_url="https://example.com")
    test_db_session.add(scan)
    
    finding = Finding(
        scan_id="test_scan_11",
        agent_id=1,
        title="Detail Vuln",
        vuln_type="test",
        category="test_cat",
        severity="low",
        affected_url="https://example.com",
        confidence=50,
        verdict="Inconclusive",
        false_positive=False
    )
    test_db_session.add(finding)
    test_db_session.commit()

    # Test valid
    response = client.get(f"/api/findings/detail/{finding.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == finding.id
    assert data["verdict"] == "Inconclusive"
    
    # Test invalid
    response_404 = client.get("/api/findings/detail/nonexistent_id")
    assert response_404.status_code == 404
