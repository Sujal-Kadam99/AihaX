"""AihaX Reconnaissance Orchestrator, Differential Analysis, and RECON_ONLY Mode Tests."""

from __future__ import annotations

import pytest

from backend.core.scope_validator import ScopeValidator
from backend.recon import (
    AssetCapabilities,
    DetectedTechnology,
    DiscoveredAsset,
    DiscoveredEndpoint,
    DiscoverySource,
    EndpointType,
    ReconOrchestrator,
    ReconResult,
)
from backend.services.campaign_executor import CampaignExecutor, CampaignMode
from backend.services.request_engine import MockTransport, RequestEngine


@pytest.mark.asyncio
async def test_recon_differential_analysis():
    """Verify that scan differentials correctly identify new, removed, and changed assets/endpoints."""
    run_a = ReconResult(
        campaign_id="scan-a",
        target_domain="example.com",
        assets_in_scope=[
            DiscoveredAsset("1", "https://example.com", "https://example.com/", "example.com", "https", 443, "/", "WEB_APPLICATION", DiscoverySource.USER_INPUT, "IN_SCOPE"),
            DiscoveredAsset("2", "https://old.example.com", "https://old.example.com/", "old.example.com", "https", 443, "/", "WEB_APPLICATION", DiscoverySource.USER_INPUT, "IN_SCOPE"),
        ],
        endpoints=[
            DiscoveredEndpoint("e1", "https://example.com/login", "/login"),
            DiscoveredEndpoint("e2", "https://example.com/old_route", "/old_route"),
        ],
        technologies=[
            DetectedTechnology("Nginx", "1.18.0"),
        ],
    )

    run_b = ReconResult(
        campaign_id="scan-b",
        target_domain="example.com",
        assets_in_scope=[
            DiscoveredAsset("1", "https://example.com", "https://example.com/", "example.com", "https", 443, "/", "WEB_APPLICATION", DiscoverySource.USER_INPUT, "IN_SCOPE"),
            DiscoveredAsset("3", "https://api.example.com", "https://api.example.com/", "api.example.com", "https", 443, "/", "API", DiscoverySource.USER_INPUT, "IN_SCOPE"),
        ],
        endpoints=[
            DiscoveredEndpoint("e1", "https://example.com/login", "/login"),
            DiscoveredEndpoint("e3", "https://example.com/api/v2", "/api/v2"),
        ],
        technologies=[
            DetectedTechnology("Nginx", "1.22.1"),
        ],
    )

    diff = ReconOrchestrator.compute_differential(run_a, run_b)

    assert "https://api.example.com/" in diff.new_assets
    assert "https://old.example.com/" in diff.removed_assets
    assert "https://example.com/api/v2" in diff.new_endpoints
    assert "https://example.com/old_route" in diff.removed_endpoints
    assert "Nginx:1.22.1" in diff.new_technologies


@pytest.mark.asyncio
async def test_campaign_executor_recon_only_mode():
    """Verify that RECON_ONLY mode discovers assets and plans checks without executing checks."""
    scope = ScopeValidator(in_scope_assets=["https://example.com"])
    transport = MockTransport(
        default_status=200,
        default_headers={"Server": "nginx/1.22.0", "Content-Type": "text/html"},
        default_body=b'<html><head><title>Test App</title></head><body><a href="/api/users">Users</a></body></html>',
    )
    executor = CampaignExecutor(scope_validator=scope, transport=transport)

    result = await executor.execute_campaign(
        campaign_id="recon-only-camp",
        target_url="https://example.com",
        mode=CampaignMode.RECON_ONLY,
    )

    # RECON_ONLY invariants
    assert result.mode == "RECON_ONLY"
    assert result.assets_scanned >= 1
    assert result.checks_planned > 0
    assert result.checks_executed == 0  # Zero vulnerability checks executed
    assert result.candidates_count == 0  # Zero candidate findings
    assert result.verified_findings_count == 0
    assert len(result.findings) == 0
    assert result.recon_result is not None
    assert result.recon_result["assets_in_scope_count"] >= 1
