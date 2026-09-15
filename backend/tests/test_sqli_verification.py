import pytest
from unittest.mock import AsyncMock, MagicMock
from backend.services.verification_engine import (
    VerificationContext,
    VerificationStatus,
    VerificationReasonCode,
)
from backend.services.verification_strategies.sql_injection_strategy import SqlInjectionVerificationStrategy
from backend.services.request_engine import RequestSpec, RequestEvidence
import time

def create_context(mock_send_func) -> VerificationContext:
    context = VerificationContext(
        finding_id="f-123",
        check_id="C023_SQL_Injection",
        target_url="http://test.local/api/users",
        candidate_evidence={
            "affected_url": "http://test.local/api/users?id=1",
            "affected_param": "id",
            "payload": "1",
            "proof_request": "GET /api/users?id=1 HTTP/1.1\r\nHost: test.local\r\n\r\n"
        },
        request_engine=MagicMock(),
        auth_context=None,
        budget=None,
        authorization_confirmed=True
    )
    context.send_verification_request = AsyncMock(side_effect=mock_send_func)
    return context

def mock_request_evidence(request_id: str, success: bool, body: str) -> RequestEvidence:
    ev = MagicMock(spec=RequestEvidence)
    ev.request_id = request_id
    ev.success = success
    ev.response_body = body
    ev.response_status = 200 if success else 500
    return ev

@pytest.mark.asyncio
async def test_sqli_strategy_vulnerable_flat():
    async def mock_send(spec: RequestSpec):
        if "id=%27" in spec.url or "id='" in spec.url:
            if "OR" in spec.url:
                if "1'='1" in spec.url or "1%27%3D%271" in spec.url or "1%27+%3D+%271" in spec.url or "%271%27%3D%271" in spec.url:
                    return mock_request_evidence("req-true", True, '{"user": "admin", "padding": "' + "A" * 100 + '"}')
                elif "1%27%3D%270" in spec.url or "1'='0" in spec.url:
                    return mock_request_evidence("req-false", True, '{"users": []}')
            else:
                return mock_request_evidence("req-error", True, "Generic server error")
        else:
            return mock_request_evidence("req-base", True, '{"user": "admin", "padding": "' + "A" * 100 + '"}')

    context = create_context(mock_send)
    strategy = SqlInjectionVerificationStrategy()
    conclusion = await strategy.verify(context)
    
    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.REPRODUCED_SUCCESSFULLY
    assert "flat" in conclusion.reason_description or "collapse" in conclusion.reason_description

@pytest.mark.asyncio
async def test_sqli_strategy_safe():
    async def mock_send(spec: RequestSpec):
        if "id=%27" in spec.url or "id='" in spec.url or "OR" in spec.url or "%20OR%20" in spec.url:
            return mock_request_evidence("req-safe", True, '{"error": "Invalid format"}')
        else:
            return mock_request_evidence("req-base", True, '{"user": "admin"}')

    context = create_context(mock_send)
    strategy = SqlInjectionVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.INCONCLUSIVE
    assert conclusion.reason_code == VerificationReasonCode.CONTRADICTORY_EVIDENCE

@pytest.mark.asyncio
async def test_sqli_strategy_dynamic_content_safe():
    counter = {"count": 0}
    
    async def mock_send(spec: RequestSpec):
        counter["count"] += 1
        dynamic_padding = "A" * (counter["count"] * 100) 
        
        if "id=%27" in spec.url or "id='" in spec.url or "OR" in spec.url or "%20OR%20" in spec.url:
            return mock_request_evidence(f"req-{counter['count']}", True, f'{{"user": "admin", "ad": "{dynamic_padding}"}}')
        else:
            return mock_request_evidence(f"req-base-{counter['count']}", True, f'{{"user": "admin", "ad": "{dynamic_padding}"}}')

    context = create_context(mock_send)
    strategy = SqlInjectionVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.INCONCLUSIVE
    assert conclusion.reason_code == VerificationReasonCode.CONTRADICTORY_EVIDENCE

@pytest.mark.asyncio
async def test_sqli_strategy_vulnerable_expand():
    # Tests the pattern where TRUE returns vastly more data than BASELINE
    async def mock_send(spec: RequestSpec):
        if "id=%27" in spec.url or "id='" in spec.url:
            if "OR" in spec.url:
                if "1'='1" in spec.url or "1%27%3D%271" in spec.url or "1%27+%3D+%271" in spec.url or "%271%27%3D%271" in spec.url:
                    # True expands vastly
                    many_users = ", ".join([f'{{"user": "user{i}"}}' for i in range(100)])
                    return mock_request_evidence("req-true", True, f"[{many_users}]")
                elif "1%27%3D%270" in spec.url or "1'='0" in spec.url:
                    # False collapses
                    return mock_request_evidence("req-false", True, '[]')
            else:
                return mock_request_evidence("req-error", True, "Generic server error")
        else:
            # Baseline returns 1 user
            return mock_request_evidence("req-base", True, '[{"user": "admin"}]')

    context = create_context(mock_send)
    strategy = SqlInjectionVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.REPRODUCED_SUCCESSFULLY
    assert "expand" in conclusion.reason_description or "collapse" in conclusion.reason_description
