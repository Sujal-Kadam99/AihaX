import pytest
import json
from unittest.mock import AsyncMock
from backend.services.verification_engine import (
    VerificationContext,
    VerificationBudget,
    VerificationStatus,
    VerificationReasonCode,
)
from backend.models.database import Finding
from backend.services.request_engine import RequestEngine, RequestEvidence
from backend.services.verification_strategies.mass_assignment_strategy import MassAssignmentVerificationStrategy
from backend.services.verification_strategies.parameter_tampering_strategy import ParameterTamperingVerificationStrategy
from backend.services.verification_strategies.race_condition_strategy import RaceConditionVerificationStrategy

def make_evidence(request_id, response_status, response_body, success=True):
    return RequestEvidence(
        request_id=request_id,
        timestamp="2023-01-01T00:00:00Z",
        method="GET",
        url="http://test",
        request_headers={},
        request_body=None,
        response_status=response_status,
        response_headers={},
        response_body=response_body,
        response_size=len(response_body),
        duration_ms=10.0,
        truncated=False,
        redirect_chain=[],
        scope_decision={"allowed": True},
        transport_error=None,
        request_hash="hash",
        response_hash="hash",
        success=success
    )

@pytest.fixture
def mock_request_engine():
    engine = AsyncMock(spec=RequestEngine)
    engine.execute = AsyncMock()
    return engine

@pytest.fixture
def default_budget():
    return VerificationBudget(max_requests=10, max_duration_seconds=30.0)

# --- Mass Assignment ---

@pytest.mark.asyncio
async def test_mass_assignment_verified(mock_request_engine, default_budget):
    payload = json.dumps({"name": "Test", "is_admin": True})
    ctx = VerificationContext("F1", "http://test/api/user", {"payload": payload}, mock_request_engine, "C070", budget=default_budget)
    
    # Baseline returns normal user (no is_admin)
    baseline_evidence = make_evidence("R1", 200, '{"name": "Test"}')
    # Malicious returns injected is_admin
    malicious_evidence = make_evidence("R2", 200, '{"name": "Test", "is_admin": true}')
    mock_request_engine.execute.side_effect = [baseline_evidence, malicious_evidence]

    strategy = MassAssignmentVerificationStrategy()
    conclusion = await strategy.verify(ctx)
    
    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.PROPERTY_DEMONSTRATED
    assert conclusion.confidence == 95

@pytest.mark.asyncio
async def test_mass_assignment_false_positive(mock_request_engine, default_budget):
    payload = json.dumps({"name": "Test", "is_admin": True})
    ctx = VerificationContext("F1", "http://test/api/user", {"payload": payload}, mock_request_engine, "C070", budget=default_budget)
    
    # Both return is_admin (default state)
    resp_evidence = make_evidence("R1", 200, '{"name": "Test", "is_admin": true}')
    mock_request_engine.execute.side_effect = [resp_evidence, resp_evidence]

    strategy = MassAssignmentVerificationStrategy()
    conclusion = await strategy.verify(ctx)
    
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE
    assert conclusion.reason_code == VerificationReasonCode.CONTRADICTORY_EVIDENCE

# --- Parameter Tampering ---

@pytest.mark.asyncio
async def test_parameter_tampering_verified(mock_request_engine, default_budget):
    ctx = VerificationContext("F2", "http://test/api/buy?price=10", {"observed_data": {"parameter": "price"}}, mock_request_engine, "C073", budget=default_budget)
    
    tampered_evidence = make_evidence("R1", 200, "Success")
    mock_request_engine.execute.return_value = tampered_evidence

    strategy = ParameterTamperingVerificationStrategy()
    conclusion = await strategy.verify(ctx)
    
    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.PROPERTY_DEMONSTRATED
    assert mock_request_engine.execute.call_count == 1
    # Verify the URL used for request
    spec = mock_request_engine.execute.call_args[0][0]
    assert "price=-1.00" in spec.url

@pytest.mark.asyncio
async def test_parameter_tampering_false_positive(mock_request_engine, default_budget):
    ctx = VerificationContext("F2", "http://test/api/buy?price=10", {"observed_data": {"parameter": "price"}}, mock_request_engine, "C073", budget=default_budget)
    
    tampered_evidence = make_evidence("R1", 400, "Invalid price")
    mock_request_engine.execute.return_value = tampered_evidence

    strategy = ParameterTamperingVerificationStrategy()
    conclusion = await strategy.verify(ctx)
    
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE
    assert conclusion.reason_code == VerificationReasonCode.CONTROL_ENFORCED

# --- Race Condition ---

@pytest.mark.asyncio
async def test_race_condition_verified(mock_request_engine, default_budget):
    # Needs permit_race_condition_testing = True
    ctx = VerificationContext("F3", "http://test/api/redeem", {"observed_data": {"permit_race_condition_testing": True}}, mock_request_engine, "C075", budget=default_budget)
    
    # All 5 succeed
    success_evidence = make_evidence("R1", 200, "Redeemed")
    mock_request_engine.execute.side_effect = [success_evidence] * 5

    strategy = RaceConditionVerificationStrategy()
    conclusion = await strategy.verify(ctx)
    
    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.PROPERTY_DEMONSTRATED
    assert conclusion.confidence == 95

@pytest.mark.asyncio
async def test_race_condition_safeguard(mock_request_engine, default_budget):
    # permit_race_condition_testing is missing/False
    ctx = VerificationContext("F3", "http://test/api/redeem", {"observed_data": {}}, mock_request_engine, "C075", budget=default_budget)
    
    strategy = RaceConditionVerificationStrategy()
    conclusion = await strategy.verify(ctx)
    
    assert conclusion.status == VerificationStatus.INCONCLUSIVE
    assert conclusion.reason_code == VerificationReasonCode.OUT_OF_SCOPE_BLOCKED
    assert mock_request_engine.execute.call_count == 0
