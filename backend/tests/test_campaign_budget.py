"""Tests for Campaign Request Budgeting and Concurrency Boundaries."""

import asyncio
import pytest
from backend.core.scope_validator import ScopeValidator
from backend.services.campaign_executor import (
    CampaignExecutor,
    CampaignRequestBudget,
)
from backend.services.request_engine import (
    MockTransport,
    RawResponse,
)


@pytest.mark.asyncio
async def test_campaign_request_budget_exhaustion():
    budget = CampaignRequestBudget(campaign_budget=5, target_budget=10, check_budget=10)

    # First 5 requests succeed
    for _ in range(5):
        allowed, reason = await budget.can_request("https://target.com", "C001")
        assert allowed is True
        await budget.record_request("https://target.com", "C001")

    # 6th request must be rejected
    allowed, reason = await budget.can_request("https://target.com", "C001")
    assert allowed is False
    assert "Campaign budget exhausted" in reason
    assert budget.requests_remaining == 0
    assert len(budget.budget_events) >= 1


@pytest.mark.asyncio
async def test_target_request_budget_exhaustion():
    budget = CampaignRequestBudget(campaign_budget=50, target_budget=3, check_budget=10)

    # 3 requests on Target A
    for _ in range(3):
        allowed, _ = await budget.can_request("https://target-a.com", "C001")
        assert allowed is True
        await budget.record_request("https://target-a.com", "C001")

    # 4th request on Target A fails
    allowed_a, reason_a = await budget.can_request("https://target-a.com", "C001")
    assert allowed_a is False
    assert "Target budget exhausted" in reason_a

    # But Target B still has available budget
    allowed_b, _ = await budget.can_request("https://target-b.com", "C001")
    assert allowed_b is True


@pytest.mark.asyncio
async def test_executor_stops_when_campaign_budget_exceeded():
    scope = ScopeValidator(in_scope_assets=["https://example.com"])
    transport = MockTransport(default_status=200, default_headers={}, default_body=b"OK")

    # Set tiny campaign budget of 2
    executor = CampaignExecutor(
        scope_validator=scope,
        transport=transport,
        campaign_budget=2,
        target_budget=2,
        check_budget=1,
    )

    result = await executor.execute_campaign(
        campaign_id="camp-budget-test",
        target_url="https://example.com",
        selected_checks=["C001_Open_Port_80", "C002_Missing_Security_Headers", "C003_Sensitive_Files_Exposure", "C004_CORS_Misconfiguration"],
    )

    # Exactly 2 checks executed before budget stopped further requests
    assert result.requests_used == 2
    assert len(result.budget_events) >= 1
