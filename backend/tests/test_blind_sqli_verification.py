import pytest
import time
from unittest.mock import AsyncMock, MagicMock
from backend.services.verification_engine import (
    VerificationContext,
    VerificationStatus,
    VerificationReasonCode,
    VerificationBudget,
)
from backend.services.verification_strategies.blind_sql_injection_strategy import BlindSqlInjectionVerificationStrategy
from backend.services.request_engine import RequestSpec, RequestEvidence

def create_context(mock_send_func) -> VerificationContext:
    context = VerificationContext(
        finding_id="f-124",
        check_id="C024_Blind_SQL_Injection",
        target_url="http://test.local/api/users",
        candidate_evidence={
            "affected_url": "http://test.local/api/users?id=1",
            "affected_param": "id",
            "payload": "1",
            "proof_request": "GET /api/users?id=1 HTTP/1.1\r\nHost: test.local\r\n\r\n"
        },
        request_engine=MagicMock(),
        auth_context=None,
        budget=VerificationBudget(max_requests=10, max_duration_seconds=30.0),
        authorization_confirmed=True
    )
    context.requests_made = 0
    
    async def wrapped_send(spec):
        context.requests_made += 1
        return await mock_send_func(spec)
        
    context.send_verification_request = AsyncMock(side_effect=wrapped_send)
    return context

def mock_request_evidence(request_id: str, success: bool, duration_ms: float) -> RequestEvidence:
    ev = MagicMock(spec=RequestEvidence)
    ev.request_id = request_id
    ev.success = success
    ev.duration_ms = duration_ms
    ev.response_status = 200 if success else 500
    ev.response_body = '{"user": "admin"}'
    return ev

@pytest.mark.asyncio
async def test_blind_sqli_vulnerable():
    # Vulnerable case: sleep payload reliably adds ~5s delay across two independent requests
    async def mock_send(spec: RequestSpec):
        if "SLEEP" in spec.url and "5" in spec.url or "pg_sleep" in spec.url and "5" in spec.url or "DELAY" in spec.url and "0:0:5" in spec.url:
            return mock_request_evidence("req-sleep", True, 5200.0) # 5.2s
        elif "SLEEP" in spec.url and "0" in spec.url or "pg_sleep" in spec.url and "0" in spec.url or "DELAY" in spec.url and "0:0:0" in spec.url:
            return mock_request_evidence("req-control", True, 110.0) # 110ms
        else:
            return mock_request_evidence("req-base", True, 100.0) # 100ms baseline

    context = create_context(mock_send)
    strategy = BlindSqlInjectionVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.REPRODUCED_SUCCESSFULLY
    assert len(conclusion.request_ids) > 0

@pytest.mark.asyncio
async def test_blind_sqli_safe():
    # Safe case: all payloads return near-baseline latency
    async def mock_send(spec: RequestSpec):
        if "SLEEP" in spec.url and "5" in spec.url or "pg_sleep" in spec.url and "5" in spec.url or "DELAY" in spec.url and "0:0:5" in spec.url:
            return mock_request_evidence("req-sleep", True, 120.0) # Ignored
        elif "SLEEP" in spec.url and "0" in spec.url or "pg_sleep" in spec.url and "0" in spec.url or "DELAY" in spec.url and "0:0:0" in spec.url:
            return mock_request_evidence("req-control", True, 110.0)
        else:
            return mock_request_evidence("req-base", True, 100.0)

    context = create_context(mock_send)
    strategy = BlindSqlInjectionVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.INCONCLUSIVE
    assert conclusion.reason_code == VerificationReasonCode.CONTRADICTORY_EVIDENCE

@pytest.mark.asyncio
async def test_blind_sqli_flaky():
    # Flaky/non-reproducible case: sleep payload is slow on the first request but NOT on the second
    counter = {"count": 0}
    
    async def mock_send(spec: RequestSpec):
        if "SLEEP" in spec.url and "5" in spec.url or "pg_sleep" in spec.url and "5" in spec.url or "DELAY" in spec.url and "0:0:5" in spec.url:
            counter["count"] += 1
            if counter["count"] == 1:
                return mock_request_evidence("req-sleep-1", True, 5200.0)
            else:
                return mock_request_evidence("req-sleep-2", True, 150.0) # Failed reproduction
        elif "SLEEP" in spec.url and "0" in spec.url or "pg_sleep" in spec.url and "0" in spec.url or "DELAY" in spec.url and "0:0:0" in spec.url:
            return mock_request_evidence("req-control", True, 110.0)
        else:
            return mock_request_evidence("req-base", True, 100.0)

    context = create_context(mock_send)
    strategy = BlindSqlInjectionVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.INCONCLUSIVE
    assert conclusion.reason_code == VerificationReasonCode.CONTRADICTORY_EVIDENCE

@pytest.mark.asyncio
async def test_blind_sqli_noisy_baseline():
    # Noisy baseline case: baseline itself is > 2s
    async def mock_send(spec: RequestSpec):
        return mock_request_evidence("req-base", True, 2500.0) # 2.5s baseline

    context = create_context(mock_send)
    strategy = BlindSqlInjectionVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.INCONCLUSIVE
    assert conclusion.reason_code == VerificationReasonCode.CONTRADICTORY_EVIDENCE

@pytest.mark.asyncio
async def test_blind_sqli_timeout_evidence():
    # Test that when a timeout is used as evidence, it is added to successful_request_ids
    async def mock_send(spec: RequestSpec):
        if "SLEEP" in spec.url and "5" in spec.url or "pg_sleep" in spec.url and "5" in spec.url or "DELAY" in spec.url and "0:0:5" in spec.url:
            raise TimeoutError("readtimeout occurred")
        elif "SLEEP" in spec.url and "0" in spec.url or "pg_sleep" in spec.url and "0" in spec.url or "DELAY" in spec.url and "0:0:0" in spec.url:
            return mock_request_evidence("req-control", True, 110.0)
        else:
            return mock_request_evidence("req-base", True, 100.0)

    context = create_context(mock_send)
    strategy = BlindSqlInjectionVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.VERIFIED
    # Should include 1 base, 1 control, and 2 timeouts
    assert len(conclusion.request_ids) == 4
    assert any("timeout-" in req_id for req_id in conclusion.request_ids)


@pytest.mark.asyncio
async def test_blind_sqli_budget_exhaustion():
    # Budget exhausted case
    async def mock_send(spec: RequestSpec):
        return mock_request_evidence("req-base", True, 120.0)

    context = create_context(mock_send)
    context.requests_made = 10 # Artificially exhaust the budget
    
    strategy = BlindSqlInjectionVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.INCONCLUSIVE
    assert conclusion.reason_code == VerificationReasonCode.BUDGET_EXHAUSTED
