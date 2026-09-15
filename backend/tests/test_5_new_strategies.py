import pytest
import re
from unittest.mock import AsyncMock, patch

from backend.services.verification_engine import (
    VerificationContext,
    VerificationBudget,
    VerificationStatus,
    VerificationReasonCode,
)
from backend.services.request_engine import RequestEngine, RequestEvidence
from backend.services.verification_strategies.csrf_strategy import CsrfVerificationStrategy
from backend.services.verification_strategies.cors_strategy import CorsVerificationStrategy
from backend.services.verification_strategies.jwt_strategy import JwtVerificationStrategy
from backend.services.verification_strategies.file_upload_strategy import FileUploadVerificationStrategy
from backend.services.verification_strategies.xxe_strategy import XxeVerificationStrategy

@pytest.fixture
def mock_request_engine():
    engine = RequestEngine()
    engine.execute = AsyncMock()
    return engine

@pytest.fixture
def mock_budget():
    return VerificationBudget(max_requests=5, max_duration_seconds=30)

@pytest.mark.asyncio
async def test_csrf_strategy_verified(mock_request_engine, mock_budget):
    candidate = {
        "affected_url": "http://example.com/update",
        "proof_request": "POST /update HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nname=admin&csrf=12345",
        "proof_response": "{'status_code': 200}"
    }
    context = VerificationContext(
        finding_id="f1", check_id="C016_Missing_SameSite_Cookie", target_url="http://example.com",
        candidate_evidence=candidate, request_engine=mock_request_engine, budget=mock_budget,
        authorization_confirmed=True
    )
    
    mock_response = RequestEvidence(
        request_id="r1", timestamp="ts", method="POST", url="u", request_headers={},
        request_body=None, response_status=200, response_headers={}, 
        response_body="OK", response_size=2, duration_ms=10.0, truncated=False,
        redirect_chain=[], scope_decision={}, transport_error=None, request_hash="",
        response_hash="", success=True
    )
    mock_request_engine.execute.return_value = mock_response
    
    strategy = CsrfVerificationStrategy()
    conclusion = await strategy.verify(context)
    
    assert conclusion.status == VerificationStatus.VERIFIED
    # Ensure csrf token was stripped in the request data
    executed_req = mock_request_engine.execute.call_args[0][0]
    assert "csrf=" not in executed_req.body

@pytest.mark.asyncio
async def test_cors_strategy_verified(mock_request_engine, mock_budget):
    candidate = {
        "affected_url": "http://example.com/api/data",
        "proof_request": "GET /api/data HTTP/1.1\r\nHost: example.com\r\n\r\n"
    }
    context = VerificationContext(
        finding_id="f1", check_id="C004_CORS_Misconfiguration", target_url="http://example.com",
        candidate_evidence=candidate, request_engine=mock_request_engine, budget=mock_budget,
        authorization_confirmed=True
    )
    
    mock_response = RequestEvidence(
        request_id="r1", timestamp="ts", method="POST", url="u", request_headers={},
        request_body=None, response_status=200, 
        response_headers={"Access-Control-Allow-Origin": "https://malicious-aihax-test.com", "Access-Control-Allow-Credentials": "true"}, 
        response_body="OK", response_size=2, duration_ms=10.0, truncated=False,
        redirect_chain=[], scope_decision={}, transport_error=None, request_hash="",
        response_hash="", success=True
    )
    mock_request_engine.execute.return_value = mock_response
    
    strategy = CorsVerificationStrategy()
    conclusion = await strategy.verify(context)
    
    assert conclusion.status == VerificationStatus.VERIFIED
    executed_req = mock_request_engine.execute.call_args[0][0]
    assert executed_req.headers["Origin"] == "https://malicious-aihax-test.com"

@pytest.mark.asyncio
async def test_jwt_strategy_verified(mock_request_engine, mock_budget):
    candidate = {
        "affected_url": "http://example.com/api/data",
        "proof_request": "GET /api/data HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\r\n\r\n"
    }
    context = VerificationContext(
        finding_id="f1", check_id="C020_JWT_Algorithm_Weakness", target_url="http://example.com",
        candidate_evidence=candidate, request_engine=mock_request_engine, budget=mock_budget,
        authorization_confirmed=True
    )
    
    mock_response = RequestEvidence(
        request_id="r1", timestamp="ts", method="POST", url="u", request_headers={},
        request_body=None, response_status=200, response_headers={}, 
        response_body="OK", response_size=2, duration_ms=10.0, truncated=False,
        redirect_chain=[], scope_decision={}, transport_error=None, request_hash="",
        response_hash="", success=True
    )
    mock_request_engine.execute.return_value = mock_response
    
    strategy = JwtVerificationStrategy()
    conclusion = await strategy.verify(context)
    
    assert conclusion.status == VerificationStatus.VERIFIED
    executed_req = mock_request_engine.execute.call_args[0][0]
    assert "eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0" in executed_req.headers["Authorization"]

@pytest.mark.asyncio
async def test_file_upload_strategy_verified(mock_request_engine, mock_budget):
    candidate = {
        "affected_url": "http://example.com/upload",
        "proof_request": "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW\r\n\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n"
    }
    context = VerificationContext(
        finding_id="f1", check_id="C055_Dangerous_File_Upload", target_url="http://example.com",
        candidate_evidence=candidate, request_engine=mock_request_engine, budget=mock_budget,
        authorization_confirmed=True
    )
    
    async def mock_execute(spec):
        if spec.method == "POST":
            # Extract the generated filename to include in the mock response
            m = re.search(r'filename="([^"]+)"', spec.body)
            fname = m.group(1) if m else "test.php"
            return RequestEvidence(
                request_id="r1", timestamp="ts", method="POST", url="u", request_headers={},
                request_body=None, response_status=200, response_headers={}, 
                response_body=f'{{"url": "http://example.com/uploads/{fname}"}}', response_size=10, duration_ms=10.0, truncated=False,
                redirect_chain=[], scope_decision={}, transport_error=None, request_hash="",
                response_hash="", success=True
            )
        else:
            # GET request
            m = re.search(r'test_(.+)\.php', spec.url)
            uuid_str = m.group(1) if m else "123"
            return RequestEvidence(
                request_id="r2", timestamp="ts", method="POST", url="u", request_headers={},
                request_body=None, response_status=200, response_headers={}, 
                response_body=f"AihaX_Upload_Test_{uuid_str}", response_size=10, duration_ms=10.0, truncated=False,
                redirect_chain=[], scope_decision={}, transport_error=None, request_hash="",
                response_hash="", success=True
            )

    mock_request_engine.execute.side_effect = mock_execute
    
    strategy = FileUploadVerificationStrategy()
    conclusion = await strategy.verify(context)
    
    assert conclusion.status == VerificationStatus.VERIFIED

@pytest.mark.asyncio
async def test_xxe_strategy_verified(mock_request_engine, mock_budget):
    candidate = {
        "affected_url": "http://example.com/api/xml",
        "proof_request": "POST /api/xml HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/xml\r\n\r\n<?xml version=\"1.0\"?><data><user>admin</user></data>"
    }
    context = VerificationContext(
        finding_id="f1", check_id="C033_XXE_Indicators", target_url="http://example.com",
        candidate_evidence=candidate, request_engine=mock_request_engine, budget=mock_budget,
        authorization_confirmed=True
    )
    
    mock_response = RequestEvidence(
        request_id="r1", timestamp="ts", method="POST", url="u", request_headers={},
        request_body=None, response_status=200, response_headers={}, 
        response_body="root:x:0:0:root:/root:/bin/bash", response_size=30, duration_ms=10.0, truncated=False,
        redirect_chain=[], scope_decision={}, transport_error=None, request_hash="",
        response_hash="", success=True
    )
    mock_request_engine.execute.return_value = mock_response
    
    strategy = XxeVerificationStrategy()
    conclusion = await strategy.verify(context)
    
    assert conclusion.status == VerificationStatus.VERIFIED
    executed_req = mock_request_engine.execute.call_args[0][0]
    assert "&xxe;" in executed_req.body
    assert "ENTITY xxe SYSTEM" in executed_req.body
