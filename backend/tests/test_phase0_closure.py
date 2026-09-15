import logging

import pytest
from fastapi.testclient import TestClient

from backend.core.auth import get_or_create_api_token
from backend.core.config import Settings
from backend.core.errors import APIException
from backend.core.logger import SensitiveDataFilter
from backend.main import app
from backend.models.schemas import APIError, APIResponse


def test_config_validation_local():
    # In local environment, dummy secrets are acceptable or missing are replaced by defaults/None
    settings = Settings(environment="local")
    assert settings.environment == "local"

def test_config_missing_cloud_secrets():
    # In cloud environment, if stripe_secret_key is missing,
    # it should raise ValidationError via model_post_init
    with pytest.raises(ValueError, match="is required in cloud environment"):
        Settings(environment="cloud", stripe_secret_key="")

def test_logger_secret_redaction():
    filter_instance = SensitiveDataFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg={"stripe_secret_key": "sk_test_123", "normal_data": "ok", "password": "supersecret"},
        args=(),
        exc_info=None
    )
    filter_instance.filter(record)
    assert record.msg["stripe_secret_key"] == "***REDACTED***"
    assert record.msg["password"] == "***REDACTED***"
    assert record.msg["normal_data"] == "ok"

@app.get("/test/expected-error")
def expected_error_route():
    raise APIException(status_code=400, error_code="BAD_REQ", message="Bad Request")

@app.get("/test/unexpected-error")
def unexpected_error_route():
    raise Exception("This is a secret unexpected error with db details")

def test_expected_api_exception(client: TestClient):
    token = get_or_create_api_token()
    response = client.get("/test/expected-error", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 400
    data = response.json()
    assert data["success"] is False
    assert data["error"]["code"] == "BAD_REQ"
    assert data["error"]["message"] == "Bad Request"

def test_unexpected_exception_redaction():
    with TestClient(app, raise_server_exceptions=False) as test_client:
        token = get_or_create_api_token()
        response = test_client.get(
            "/test/unexpected-error", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 500
        data = response.json()
        assert data["success"] is False
        assert data["error"]["code"] == "INTERNAL_SERVER_ERROR"
        # The message should be safe, not leaking the exception text
        assert data["error"]["message"] == "An unexpected error occurred."
        assert "db details" not in str(data)

def test_api_response_schema():
    # Verify contract
    err = APIError(code="TEST", message="Test msg")
    resp = APIResponse(success=False, error=err)
    assert resp.success is False
    assert resp.error.code == "TEST"
