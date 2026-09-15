"""Unit tests for Batch B verification strategies:
- DirectoryListingVerificationStrategy
- VerboseErrorVerificationStrategy
- DefaultCredentialsVerificationStrategy
"""

import pytest
import re
from unittest.mock import AsyncMock

from backend.services.verification_engine import (
    VerificationContext,
    VerificationBudget,
    VerificationStatus,
    VerificationReasonCode,
)
from backend.services.request_engine import RequestEngine, RequestEvidence
from backend.services.verification_strategies.directory_listing_strategy import DirectoryListingVerificationStrategy
from backend.services.verification_strategies.verbose_error_strategy import VerboseErrorVerificationStrategy
from backend.services.verification_strategies.default_credentials_strategy import DefaultCredentialsVerificationStrategy


@pytest.fixture
def mock_request_engine():
    engine = RequestEngine()
    engine.execute = AsyncMock()
    return engine


@pytest.fixture
def mock_budget():
    return VerificationBudget(max_requests=10, max_duration_seconds=30)


def _make_response(status=200, body="", headers=None, request_id="r1"):
    return RequestEvidence(
        request_id=request_id, timestamp="ts", method="GET", url="u",
        request_headers={}, request_body=None,
        response_status=status,
        response_headers=headers or {},
        response_body=body,
        response_size=len(body),
        duration_ms=10.0, truncated=False,
        redirect_chain=[], scope_decision={},
        transport_error=None, request_hash="", response_hash="",
        success=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Directory Listing
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_directory_listing_verified_with_sensitive_files(mock_request_engine, mock_budget):
    """Directory listing with sensitive file patterns should be VERIFIED with high confidence."""
    candidate = {
        "affected_url": "http://example.com/uploads/",
        "proof_response": "Index of /uploads/",
    }
    context = VerificationContext(
        finding_id="f1", check_id="C006_Directory_Listing",
        target_url="http://example.com",
        candidate_evidence=candidate, request_engine=mock_request_engine,
        budget=mock_budget, authorization_confirmed=True,
    )

    body = "<html><title>Index of /uploads/</title><pre>.env  config.json  backup.sql</pre></html>"
    mock_request_engine.execute.return_value = _make_response(200, body)

    strategy = DirectoryListingVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.confidence == 95
    assert ".env" in conclusion.reason_description or "config" in conclusion.reason_description


@pytest.mark.asyncio
async def test_directory_listing_verified_benign(mock_request_engine, mock_budget):
    """Directory listing without sensitive files should still be VERIFIED but lower confidence."""
    candidate = {
        "affected_url": "http://example.com/images/",
    }
    context = VerificationContext(
        finding_id="f1", check_id="C006_Directory_Listing",
        target_url="http://example.com",
        candidate_evidence=candidate, request_engine=mock_request_engine,
        budget=mock_budget, authorization_confirmed=True,
    )

    body = "<html><title>Index of /images/</title><pre>logo.png  banner.jpg  icon.svg</pre></html>"
    mock_request_engine.execute.return_value = _make_response(200, body)

    strategy = DirectoryListingVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.confidence == 80


@pytest.mark.asyncio
async def test_directory_listing_false_positive_on_403(mock_request_engine, mock_budget):
    """403 response should be FALSE_POSITIVE."""
    candidate = {"affected_url": "http://example.com/private/"}
    context = VerificationContext(
        finding_id="f1", check_id="C006_Directory_Listing",
        target_url="http://example.com",
        candidate_evidence=candidate, request_engine=mock_request_engine,
        budget=mock_budget, authorization_confirmed=True,
    )

    mock_request_engine.execute.return_value = _make_response(403, "Forbidden")

    strategy = DirectoryListingVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_directory_listing_budget_exhausted(mock_request_engine, mock_budget):
    """Zero-budget should be INCONCLUSIVE."""
    mock_budget.max_requests = 0
    candidate = {"affected_url": "http://example.com/"}
    context = VerificationContext(
        finding_id="f1", check_id="C006_Directory_Listing",
        target_url="http://example.com",
        candidate_evidence=candidate, request_engine=mock_request_engine,
        budget=mock_budget, authorization_confirmed=True,
    )

    strategy = DirectoryListingVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.INCONCLUSIVE


# ─────────────────────────────────────────────────────────────────────────────
# Verbose Error / Stack Trace
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_verbose_error_python_traceback(mock_request_engine, mock_budget):
    """Python traceback should be VERIFIED."""
    candidate = {"affected_url": "http://example.com/api/data"}
    context = VerificationContext(
        finding_id="f1", check_id="C054_Verbose_Error_Disclosure",
        target_url="http://example.com",
        candidate_evidence=candidate, request_engine=mock_request_engine,
        budget=mock_budget, authorization_confirmed=True,
    )

    body = 'Traceback (most recent call last):\n  File "/app/main.py", line 42, in handler\n    result = db.query(id)\nTypeError: bad argument'
    mock_request_engine.execute.return_value = _make_response(500, body)

    strategy = VerboseErrorVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.confidence == 95
    assert "Python Traceback" in conclusion.reason_description or "Traceback" in conclusion.reason_description


@pytest.mark.asyncio
async def test_verbose_error_java_exception(mock_request_engine, mock_budget):
    """Java exception should be VERIFIED."""
    candidate = {"affected_url": "http://example.com/api"}
    context = VerificationContext(
        finding_id="f1", check_id="C054_Verbose_Error_Disclosure",
        target_url="http://example.com",
        candidate_evidence=candidate, request_engine=mock_request_engine,
        budget=mock_budget, authorization_confirmed=True,
    )

    body = "java.lang.NullPointerException: at com.example.service.UserService.getUser(UserService.java:42)"
    mock_request_engine.execute.return_value = _make_response(500, body)

    strategy = VerboseErrorVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.VERIFIED


@pytest.mark.asyncio
async def test_verbose_error_no_stack_trace(mock_request_engine, mock_budget):
    """Generic error page without stack trace should be FALSE_POSITIVE."""
    candidate = {"affected_url": "http://example.com/api"}
    context = VerificationContext(
        finding_id="f1", check_id="C054_Verbose_Error_Disclosure",
        target_url="http://example.com",
        candidate_evidence=candidate, request_engine=mock_request_engine,
        budget=mock_budget, authorization_confirmed=True,
    )

    body = "<html><body><h1>Internal Server Error</h1><p>An error occurred.</p></body></html>"
    mock_request_engine.execute.return_value = _make_response(500, body)

    strategy = VerboseErrorVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_verbose_error_file_path_disclosure(mock_request_engine, mock_budget):
    """File path disclosure should be VERIFIED."""
    candidate = {"affected_url": "http://example.com/api"}
    context = VerificationContext(
        finding_id="f1", check_id="C054_Verbose_Error_Disclosure",
        target_url="http://example.com",
        candidate_evidence=candidate, request_engine=mock_request_engine,
        budget=mock_budget, authorization_confirmed=True,
    )

    body = "Error: Cannot open file /home/deploy/app/config/settings.py for reading"
    mock_request_engine.execute.return_value = _make_response(500, body)

    strategy = VerboseErrorVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.VERIFIED


# ─────────────────────────────────────────────────────────────────────────────
# Default Credentials
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_default_credentials_verified(mock_request_engine, mock_budget):
    """Accepted default credentials should be VERIFIED."""
    candidate = {
        "affected_url": "http://example.com/login",
        "username_field": "username",
        "password_field": "password",
    }
    context = VerificationContext(
        finding_id="f1", check_id="C012_Default_Credentials",
        target_url="http://example.com",
        candidate_evidence=candidate, request_engine=mock_request_engine,
        budget=mock_budget, authorization_confirmed=True,
    )

    # First pair (admin/admin) succeeds
    mock_request_engine.execute.return_value = _make_response(
        200, "<html>Welcome to your Dashboard! <a href='/logout'>Logout</a></html>",
        headers={"Set-Cookie": "session=abc123; Path=/"},
    )

    strategy = DefaultCredentialsVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.confidence == 95
    assert "admin" in conclusion.reason_description


@pytest.mark.asyncio
async def test_default_credentials_all_rejected(mock_request_engine, mock_budget):
    """All default credentials rejected should be FALSE_POSITIVE."""
    candidate = {
        "affected_url": "http://example.com/login",
    }
    context = VerificationContext(
        finding_id="f1", check_id="C012_Default_Credentials",
        target_url="http://example.com",
        candidate_evidence=candidate, request_engine=mock_request_engine,
        budget=mock_budget, authorization_confirmed=True,
    )

    # All pairs fail
    mock_request_engine.execute.return_value = _make_response(
        200, "<html>Login failed. Invalid username or password. <form>Login</form></html>",
    )

    strategy = DefaultCredentialsVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_default_credentials_redirect_success(mock_request_engine, mock_budget):
    """302 redirect with session cookie should be VERIFIED."""
    candidate = {
        "affected_url": "http://example.com/login",
    }
    context = VerificationContext(
        finding_id="f1", check_id="C012_Default_Credentials",
        target_url="http://example.com",
        candidate_evidence=candidate, request_engine=mock_request_engine,
        budget=mock_budget, authorization_confirmed=True,
    )

    mock_request_engine.execute.return_value = _make_response(
        302, "<html>Welcome! Redirecting to dashboard...</html>",
        headers={"Set-Cookie": "PHPSESSID=xyz789; Path=/", "Location": "/dashboard"},
    )

    strategy = DefaultCredentialsVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.VERIFIED


@pytest.mark.asyncio
async def test_default_credentials_budget_exhausted(mock_request_engine, mock_budget):
    """Zero-budget should be INCONCLUSIVE."""
    mock_budget.max_requests = 0
    candidate = {"affected_url": "http://example.com/login"}
    context = VerificationContext(
        finding_id="f1", check_id="C012_Default_Credentials",
        target_url="http://example.com",
        candidate_evidence=candidate, request_engine=mock_request_engine,
        budget=mock_budget, authorization_confirmed=True,
    )

    strategy = DefaultCredentialsVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.INCONCLUSIVE
