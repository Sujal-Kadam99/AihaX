import os

# Set required env vars BEFORE any backend imports so get_settings() succeeds at module load time
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-pytest-only")
os.environ.setdefault("AIHAX_MASTER_KEY", "test-master-key-for-pytest-only")
os.environ.setdefault("DATABASE_URL", "sqlite:///")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.models.database import Base

from backend.main import app


@pytest.fixture
def client():
    with TestClient(app) as client:
        yield client


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def reset_redis_state():
    """
    Prevents INTER-TEST LIFECYCLE INTERACTION.
    Async tests or isolated TestClients can leave a global redis connection 
    tied to a closed event loop. This clears the global state between tests
    so subsequent TestClient lifespans don't attempt to close dead connections.
    """
    yield
    from backend.core import redis_client
    redis_client._redis_client = None
    redis_client._redis_available = None

@pytest.fixture(autouse=True)
def mock_chroma(monkeypatch):
    def mock_query(*args, **kwargs):
        return []
    import backend.core.chroma_client
    monkeypatch.setattr(backend.core.chroma_client, 'query_similar', mock_query)
