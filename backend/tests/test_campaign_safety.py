"""Tests for Production Safe Mode and Security Boundaries."""

import json
import pytest
from backend.core.scope_validator import ScopeValidator
from backend.services.campaign_executor import CampaignExecutor
from backend.services.request_engine import (
    AuthenticationContext,
    MockTransport,
    RawResponse,
    RequestSpec,
)


@pytest.mark.asyncio
async def test_safe_mode_default_is_true():
    scope = ScopeValidator(in_scope_assets=["https://example.com"])
    executor = CampaignExecutor(scope_validator=scope)
    assert executor.safe_mode is True


@pytest.mark.asyncio
async def test_secret_redaction_in_audit_logs():
    scope = ScopeValidator(in_scope_assets=["https://example.com"])
    transport = MockTransport(
        default_status=200,
        default_headers={"Set-Cookie": "session_id=super_secret_session_token_xyz123; Secure; HttpOnly"},
        default_body=b"OK",
    )
    executor = CampaignExecutor(scope_validator=scope, transport=transport)

    auth = AuthenticationContext(
        name="user_a",
        cookies={"auth_token": "secret_cookie_value_999"},
        headers={"Authorization": "Bearer sensitive_jwt_token_abc_123", "X-API-Key": "secret_key_888"},
    )

    result = await executor.execute_campaign(
        campaign_id="camp-safety-test",
        target_url="https://example.com",
        selected_checks=["C002_Missing_Security_Headers"],
        auth_contexts={"user_a": auth},
    )

    # Convert audit trail to JSON string and verify sensitive values are NOT present
    audit_json = json.dumps(result.audit_trail)
    assert "sensitive_jwt_token_abc_123" not in audit_json
    assert "secret_cookie_value_999" not in audit_json
    assert "secret_key_888" not in audit_json


@pytest.mark.asyncio
async def test_ssrf_safety_policy_blocks_metadata_addresses():
    # Verify that ScopeValidator + Safe Mode default reject metadata targets
    scope = ScopeValidator(in_scope_assets=["https://example.com"])
    dec_meta = scope.validate_target("http://169.254.169.254/latest/meta-data")
    assert dec_meta.allowed is False

    dec_priv = scope.validate_target("http://192.168.1.1/admin")
    assert dec_priv.allowed is False

    dec_local = scope.validate_target("http://localhost:8080/internal")
    assert dec_local.allowed is False
