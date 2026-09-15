import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from backend.agents.verify_agent import VerifyAgent
from backend.models.database import Finding, Scan
from backend.services.request_engine import MockTransport, RequestEngine
from backend.services.verification_engine import (
    VerificationEngine,
    VerificationStatus,
    VerificationReasonCode,
)


@pytest.fixture
def mock_db_session():
    return MagicMock()


@pytest.fixture
def verify_agent(mock_db_session):
    agent = VerifyAgent(scan_id="test_scan", db=mock_db_session, config={"target_url": "https://app.example.com"})
    agent.publish_update = AsyncMock()
    agent.check_cancelled = AsyncMock()
    return agent


@pytest.mark.asyncio
async def test_verification_pipeline_verified():
    agent = VerifyAgent(scan_id="test_scan", db=MagicMock(), config={})
    finding = Finding(
        confidence=80,
        payload="test_payload",
        proof_response="secret_proof_reproduced",
        vuln_type="generic_reproducibility",
        affected_url="https://app.example.com/test",
    )
    
    mock_transport = MockTransport()
    mock_transport.register_response("https://app.example.com/test", status_code=200, body="secret_proof_reproduced")
    
    with patch("backend.agents.verify_agent.RequestEngine") as MockRE:
        instance = MockRE.return_value
        instance.execute = AsyncMock(return_value=MagicMock(
            success=True,
            response_status=200,
            response_body="secret_proof_reproduced",
            response_headers={},
            truncated=False,
            transport_error=None,
            request_id="REQ-1",
        ))
        await agent._run_verification_pipeline(finding)
        
    assert finding.verdict == "Verified"
    assert finding.false_positive is False
    assert finding.verification_status == "VERIFIED"


@pytest.mark.asyncio
async def test_verification_pipeline_potential():
    agent = VerifyAgent(scan_id="test_scan", db=MagicMock(), config={})
    finding = Finding(
        confidence=70,
        payload="test_payload",
        proof_response="",  # missing proof
        vuln_type="generic_reproducibility",
        affected_url="https://app.example.com/test",
    )
    
    await agent._run_verification_pipeline(finding)
        
    assert finding.verdict == "Inconclusive"
    assert finding.verification_status == "INCONCLUSIVE"
    assert finding.false_positive is False


@pytest.mark.asyncio
async def test_verification_pipeline_inconclusive():
    agent = VerifyAgent(scan_id="test_scan", db=MagicMock(), config={})
    finding = Finding(
        confidence=50,
        payload=None,
        proof_response=None,
        vuln_type="generic_reproducibility",
        affected_url="https://app.example.com/test",
    )
    
    await agent._run_verification_pipeline(finding)
        
    assert finding.verdict == "Inconclusive"
    assert finding.verification_status == "INCONCLUSIVE"


@pytest.mark.asyncio
async def test_verification_pipeline_chroma_false_positive():
    agent = VerifyAgent(scan_id="test_scan", db=MagicMock(), config={})
    finding = Finding(
        confidence=70,
        payload="fp_payload",
        proof_response="proof",
        vuln_type="generic_reproducibility",
        affected_url="https://app.example.com/missing",
    )
    
    with patch("backend.agents.verify_agent.RequestEngine") as MockRE:
        instance = MockRE.return_value
        instance.execute = AsyncMock(return_value=MagicMock(
            success=True,
            response_status=404,  # Contradicted by 404
            response_body="404 Not Found",
            response_headers={},
            truncated=False,
            transport_error=None,
            request_id="REQ-404",
        ))
        await agent._run_verification_pipeline(finding)
        
    assert finding.verdict == "Likely False Positive"
    assert finding.false_positive is True
    assert finding.verification_status == "FALSE_POSITIVE"


@pytest.mark.asyncio
async def test_verify_agent_execute(verify_agent, mock_db_session):
    finding_1 = Finding(
        title="F1", confidence=80, payload="P1", proof_response="R1",
        vuln_type="generic_reproducibility", affected_url="https://app.example.com/f1"
    )
    finding_2 = Finding(
        title="F2", confidence=20, payload=None, proof_response=None,
        vuln_type="generic_reproducibility", affected_url="https://app.example.com/f2"
    )
    
    scan = Scan(id="test_scan", total_findings=0)
    
    mock_query = mock_db_session.query.return_value
    mock_filter = mock_query.filter_by.return_value
    
    def side_effect(*args, **kwargs):
        if "false_positive" in kwargs:
            mock_filter.all.return_value = [finding_1, finding_2]
            return mock_filter
        else:
            mock_filter.first.return_value = scan
            return mock_filter

    mock_query.filter_by.side_effect = side_effect
    
    with patch("backend.agents.verify_agent.RequestEngine") as MockRE:
        instance = MockRE.return_value
        instance.execute = AsyncMock(return_value=MagicMock(
            success=True,
            response_status=200,
            response_body="R1",
            response_headers={},
            truncated=False,
            transport_error=None,
            request_id="REQ-1",
        ))
        result = await verify_agent.execute()
        
    assert result["verified"] == 1
    assert result["inconclusive"] == 1
    assert scan.total_findings == 1
