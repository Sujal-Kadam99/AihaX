"""Tests for Campaign Scope Enforcement and Default-Deny Security Invariants."""

import pytest
from backend.core.scope_validator import ScopeValidator
from backend.services.campaign_executor import AssetNormalizer, CampaignExecutor
from backend.services.request_engine import (
    MockTransport,
    RawResponse,
    RequestSpec,
)


@pytest.mark.asyncio
async def test_campaign_default_deny_zero_network_calls_for_out_of_scope_target():
    scope = ScopeValidator(
        in_scope_assets=["https://authorized-client.com"],
        out_of_scope_assets=["https://unauthorized-victim.com"],
    )
    transport = MockTransport(default_status=200, default_headers={}, default_body=b"OK")
    executor = CampaignExecutor(scope_validator=scope, transport=transport)

    result = await executor.execute_campaign(
        campaign_id="test-camp-001",
        target_url="https://unauthorized-victim.com",
    )

    assert result.assets_scanned == 0
    assert result.assets_skipped == 1
    assert result.requests_used == 0
    assert len(transport.calls) == 0
    assert len(result.safety_events) >= 1
    assert result.safety_events[0]["action"] == "target_blocked_out_of_scope"


@pytest.mark.asyncio
async def test_campaign_multi_asset_scope_filtering():
    scope = ScopeValidator(
        in_scope_assets=["https://app.example.com", "https://api.example.com"],
        out_of_scope_assets=["https://billing.example.com"],
    )
    transport = MockTransport(default_status=200, default_headers={}, default_body=b"OK")
    executor = CampaignExecutor(scope_validator=scope, transport=transport)

    result = await executor.execute_campaign(
        campaign_id="test-camp-002",
        target_url="https://app.example.com",
        discovered_assets=[
            "https://api.example.com",
            "https://billing.example.com",     # Explicit out of scope
            "https://thirdparty-cdn.com",       # Default deny
        ],
        selected_checks=["C002_Missing_Security_Headers"],
    )

    assert result.assets_scanned == 2  # app.example.com and api.example.com
    assert result.assets_skipped == 2  # billing.example.com and thirdparty-cdn.com
    assert result.checks_planned == 2


@pytest.mark.asyncio
async def test_asset_normalization_preserves_subdomain_isolation():
    raw_assets = [
        "https://example.com/",
        "https://example.com",
        "https://api.example.com",
        "https://api.example.com:443",
        "http://example.com:80/",
    ]
    canonical = AssetNormalizer.deduplicate_assets(raw_assets)
    urls = [c.canonical_url for c in canonical]

    # Distinct subdomains and schemes must remain separate
    assert "https://example.com/" in urls
    assert "https://api.example.com/" in urls
    assert "http://example.com/" in urls
    # Total distinct should be 3
    assert len(canonical) == 3
