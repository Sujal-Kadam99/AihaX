"""Unit tests for XssVerificationStrategy covering checks C037 through C046."""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch

from backend.services.verification_engine import (
    VerificationContext,
    VerificationBudget,
    VerificationStatus,
    VerificationReasonCode,
    VerificationRegistry,
)
from backend.services.request_engine import RequestEngine, RequestEvidence
from backend.services.verification_strategies.xss_strategy import (
    XssVerificationStrategy,
    MARKER_VARIABLE,
    MARKER_SCRIPT,
    MARKER_HTML_RENDER,
)


def _make_response(status=200, body="", headers=None, request_id="req-1", success=True):
    return RequestEvidence(
        request_id=request_id,
        timestamp="2026-09-17T00:00:00Z",
        method="GET",
        url="http://target.test/search",
        request_headers={},
        request_body=None,
        response_status=status,
        response_headers=headers or {"content-type": "text/html; charset=utf-8"},
        response_body=body,
        response_size=len(body),
        duration_ms=12.0,
        truncated=False,
        redirect_chain=[],
        scope_decision={"allowed": True},
        transport_error=None,
        request_hash="hash1",
        response_hash="hash2",
        success=success,
    )


@pytest.fixture
def mock_request_engine():
    engine = AsyncMock(spec=RequestEngine)
    engine.execute = AsyncMock()
    return engine


@pytest.fixture
def default_budget():
    return VerificationBudget(max_requests=10, max_duration_seconds=30.0)


# ==============================================================================
# 1. Reflected XSS (C037) & Context Tests (C040-C043)
# ==============================================================================

@pytest.mark.asyncio
async def test_reflected_xss_verified_when_browser_executes(mock_request_engine, default_budget):
    """Reflected XSS (C037) is VERIFIED when payload executes in browser runtime."""
    candidate = {
        "affected_url": "http://target.test/search?q=test",
        "affected_param": "q",
        # Mock browser runner confirming script execution
        "browser_runner": AsyncMock(return_value=(True, None)),
    }
    context = VerificationContext(
        finding_id="f-xss-1",
        check_id="C037_Reflected_XSS",
        target_url="http://target.test",
        candidate_evidence=candidate,
        request_engine=mock_request_engine,
        budget=default_budget,
        authorization_confirmed=True,
    )

    mock_request_engine.execute.return_value = _make_response(
        200, f"<html><body>Search: {MARKER_SCRIPT}</body></html>"
    )

    strategy = XssVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.PROPERTY_DEMONSTRATED
    assert conclusion.confidence == 100
    assert "Cross-Site Scripting confirmed" in conclusion.reason_description


@pytest.mark.asyncio
async def test_reflected_xss_false_positive_when_properly_encoded(mock_request_engine, default_budget):
    """Reflected XSS is FALSE_POSITIVE when server safely HTML entity encodes the probe."""
    candidate = {
        "affected_url": "http://target.test/search?q=test",
        "affected_param": "q",
    }
    context = VerificationContext(
        finding_id="f-xss-2",
        check_id="C037_Reflected_XSS",
        target_url="http://target.test",
        candidate_evidence=candidate,
        request_engine=mock_request_engine,
        budget=default_budget,
        authorization_confirmed=True,
    )

    # Server returned safely encoded probe
    mock_request_engine.execute.return_value = _make_response(
        200, "<html><body>Search: &lt;script&gt;window.__aihax_xss_verified__=true;&lt;/script&gt;</body></html>"
    )

    strategy = XssVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.FALSE_POSITIVE
    assert conclusion.reason_code == VerificationReasonCode.INPUT_SAFELY_ENCODED
    assert conclusion.confidence == 100


@pytest.mark.asyncio
async def test_reflected_xss_false_positive_when_browser_does_not_execute(mock_request_engine, default_budget):
    """Reflected XSS is FALSE_POSITIVE when reflected string does not execute in browser."""
    candidate = {
        "affected_url": "http://target.test/search?q=test",
        "affected_param": "q",
        "browser_runner": AsyncMock(return_value=(False, None)),
    }
    context = VerificationContext(
        finding_id="f-xss-3",
        check_id="C037_Reflected_XSS",
        target_url="http://target.test",
        candidate_evidence=candidate,
        request_engine=mock_request_engine,
        budget=default_budget,
        authorization_confirmed=True,
    )

    mock_request_engine.execute.return_value = _make_response(
        200, "<html><body>Search: <div>raw text without execution</div></body></html>"
    )

    strategy = XssVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.FALSE_POSITIVE
    assert conclusion.reason_code == VerificationReasonCode.CONTRADICTORY_EVIDENCE


@pytest.mark.asyncio
async def test_reflected_xss_inconclusive_when_browser_unavailable(mock_request_engine, default_budget):
    """Graceful INCONCLUSIVE fallback when browser automation fails or is missing."""
    candidate = {
        "affected_url": "http://target.test/search?q=test",
        "affected_param": "q",
        # Simulating browser launch error
        "browser_runner": AsyncMock(return_value=(False, "Playwright browser binary not found")),
    }
    context = VerificationContext(
        finding_id="f-xss-4",
        check_id="C037_Reflected_XSS",
        target_url="http://target.test",
        candidate_evidence=candidate,
        request_engine=mock_request_engine,
        budget=default_budget,
        authorization_confirmed=True,
    )

    mock_request_engine.execute.return_value = _make_response(
        200, f"<html><body>{MARKER_SCRIPT}</body></html>"
    )

    strategy = XssVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.INCONCLUSIVE
    assert conclusion.reason_code == VerificationReasonCode.HEURISTIC_ONLY_UNVERIFIED
    assert "Playwright browser binary not found" in conclusion.reason_description


# ==============================================================================
# 2. Stored XSS (C038) Two-Phase Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_stored_xss_verified_two_phase(mock_request_engine, default_budget):
    """Stored XSS (C038) executes two-phase POST -> GET verification and verifies browser execution."""
    candidate = {
        "affected_url": "http://target.test/comments",
        "browser_runner": AsyncMock(return_value=(True, None)),
    }
    context = VerificationContext(
        finding_id="f-xss-stored-1",
        check_id="C038_Stored_XSS",
        target_url="http://target.test",
        candidate_evidence=candidate,
        request_engine=mock_request_engine,
        budget=default_budget,
        authorization_confirmed=True,
    )

    post_resp = _make_response(201, '{"status": "created"}', request_id="post-1")
    get_resp = _make_response(200, f"<html><body><div>{MARKER_SCRIPT}</div></body></html>", request_id="get-1")
    mock_request_engine.execute.side_effect = [post_resp, get_resp]

    strategy = XssVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.REPRODUCED_SUCCESSFULLY
    assert mock_request_engine.execute.call_count == 2
    assert "Stored XSS confirmed" in conclusion.reason_description


# ==============================================================================
# 3. Unsafe HTML Rendering (C046) & Sub-Types (C039, C041, C044, C045)
# ==============================================================================

@pytest.mark.asyncio
async def test_unsafe_html_rendering_live_dom_verified(mock_request_engine, default_budget):
    """Unsafe HTML Rendering (C046) verifies live DOM element presence."""
    candidate = {
        "affected_url": "http://target.test/preview?md=test",
        "affected_param": "md",
        "browser_runner": AsyncMock(return_value=(True, None)),
    }
    context = VerificationContext(
        finding_id="f-xss-html-1",
        check_id="C046_Unsafe_HTML_Rendering",
        target_url="http://target.test",
        candidate_evidence=candidate,
        request_engine=mock_request_engine,
        budget=default_budget,
        authorization_confirmed=True,
    )

    mock_request_engine.execute.return_value = _make_response(
        200, f"<html><body>{MARKER_HTML_RENDER}</body></html>"
    )

    strategy = XssVerificationStrategy()
    conclusion = await strategy.verify(context)

    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.reason_code == VerificationReasonCode.PROPERTY_DEMONSTRATED
    assert "Unsafe HTML rendering confirmed" in conclusion.reason_description


@pytest.mark.asyncio
async def test_mutation_and_filter_bypass_probes_dispatched(mock_request_engine, default_budget):
    """Mutation XSS (C044) and Filter Bypass (C045) dispatch specialized probes."""
    strategy = XssVerificationStrategy()

    payload_c044, check_type_44 = strategy._select_payload_and_check_type("C044_Mutation_XSS")
    assert "<math>" in payload_c044
    assert check_type_44 == "script"

    payload_c045, check_type_45 = strategy._select_payload_and_check_type("C045_XSS_Filter_Bypass")
    assert "<sCrIpt>" in payload_c045

    payload_c041, check_type_41 = strategy._select_payload_and_check_type("C041_Attribute_Context_Injection")
    assert "onfocus=" in payload_c041


# ==============================================================================
# 4. Registry Resolution Integration Test
# ==============================================================================

def test_all_10_xss_checks_resolve_to_xss_strategy():
    """Verify all 10 XSS checks (C037–C046) resolve to XssVerificationStrategy in VerificationRegistry."""
    check_ids = [
        "C037_Reflected_XSS",
        "C038_Stored_XSS",
        "C039_DOM_XSS_Indicators",
        "C040_HTML_Context_Injection",
        "C041_Attribute_Context_Injection",
        "C042_JavaScript_Context_Injection",
        "C043_URL_Context_Injection",
        "C044_Mutation_XSS",
        "C045_XSS_Filter_Bypass",
        "C046_Unsafe_HTML_Rendering",
    ]

    for cid in check_ids:
        strat = VerificationRegistry.get_strategy(cid)
        assert strat is not None, f"Strategy missing for {cid}"
        assert isinstance(strat, XssVerificationStrategy), f"Expected XssVerificationStrategy for {cid}, got {type(strat)}"
