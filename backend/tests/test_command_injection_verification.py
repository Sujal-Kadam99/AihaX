import pytest
from unittest.mock import AsyncMock, MagicMock
from backend.services.verification_engine import (
    VerificationContext,
    VerificationStatus,
    VerificationReasonCode,
)
from backend.services.verification_strategies.command_injection_strategy import CommandInjectionVerificationStrategy
from backend.services.request_engine import RequestSpec, RequestEvidence

def create_context(mock_send_func) -> VerificationContext:
    context = VerificationContext(
        finding_id="f-123",
        check_id="C026_OS_Command_Injection",
        target_url="http://test.local/api/ping",
        candidate_evidence={
            "affected_url": "http://test.local/api/ping",
            "affected_param": "ip",
            "payload": "127.0.0.1; id",
            "proof_request": "POST http://test.local/api/ping\nContent-Type: application/x-www-form-urlencoded\n\nip=127.0.0.1%3B+id"
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
async def test_cmd_injection_vulnerable_uid_gid():
    async def mock_send(spec: RequestSpec):
        if "id" in (spec.body or "") or "id" in spec.url:
            return mock_request_evidence("req-test", True, "uid=33(www-data) gid=33(www-data) groups=33(www-data)")
        else:
            return mock_request_evidence("req-base", True, "PING 127.0.0.1 (127.0.0.1): 56 data bytes")

    context = create_context(mock_send)
    strategy = CommandInjectionVerificationStrategy()
    conclusion = await strategy.verify(context)
    
    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.REPRODUCED_SUCCESSFULLY
    assert conclusion.confidence == 100

@pytest.mark.asyncio
async def test_cmd_injection_not_vulnerable():
    async def mock_send(spec: RequestSpec):
        return mock_request_evidence("req", True, "PING 127.0.0.1 (127.0.0.1): 56 data bytes")

    context = create_context(mock_send)
    strategy = CommandInjectionVerificationStrategy()
    conclusion = await strategy.verify(context)
    
    assert conclusion.status == VerificationStatus.INCONCLUSIVE
    assert conclusion.reason_code == VerificationReasonCode.INCONSISTENT_BEHAVIOR
    assert conclusion.confidence == 30

@pytest.mark.asyncio
async def test_cmd_injection_contradiction_false_positive():
    # If the marker appears in the baseline request (e.g. they literally echoed the string without executing)
    async def mock_send(spec: RequestSpec):
        return mock_request_evidence("req", True, "Here is the output: uid=33(www-data) gid=33(www-data)")

    context = create_context(mock_send)
    strategy = CommandInjectionVerificationStrategy()
    conclusion = await strategy.verify(context)
    
    assert conclusion.status == VerificationStatus.REJECTED
    assert conclusion.reason_code == VerificationReasonCode.INCONSISTENT_BEHAVIOR
    assert conclusion.confidence == 95

@pytest.mark.asyncio
async def test_cmd_injection_windows_marker():
    async def mock_send(spec: RequestSpec):
        if "ipconfig" in (spec.body or "") or "ipconfig" in spec.url:
            return mock_request_evidence("req-test", True, "Windows IP Configuration\nEthernet adapter")
        else:
            return mock_request_evidence("req-base", True, "pinging 127.0.0.1")

    context = create_context(mock_send)
    context.candidate_evidence["payload"] = "127.0.0.1 & ipconfig"
    context.candidate_evidence["proof_request"] = "POST http://test.local/api/ping\nContent-Type: application/x-www-form-urlencoded\n\nip=127.0.0.1+%26+ipconfig"
    strategy = CommandInjectionVerificationStrategy()
    conclusion = await strategy.verify(context)
    
    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.REPRODUCED_SUCCESSFULLY
