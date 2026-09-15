"""AihaX Reconnaissance Safety, Scope Boundary, and Zero Network Byte Tests."""

from __future__ import annotations

import json
import pytest

from backend.core.scope_validator import ScopeValidator
from backend.recon import (
    AssetDiscoveryEngine,
    DiscoveredAsset,
    DiscoverySource,
    HttpProbeEngine,
    ReconOrchestrator,
    TechnologyDetector,
)
from backend.services.request_engine import MockTransport, RequestEngine, RequestSpec


@pytest.mark.asyncio
async def test_zero_network_bytes_for_discovered_out_of_scope_assets():
    """Prove that an out-of-scope asset discovered during recon receives ZERO network bytes."""
    scope = ScopeValidator(
        in_scope_assets=["https://authorized-client.com"],
        out_of_scope_assets=["https://unauthorized-victim.com"],
    )
    transport = MockTransport(default_status=200, default_headers={}, default_body=b"OK")
    engine = RequestEngine(scope_validator=scope, transport=transport)

    recon_orch = ReconOrchestrator(request_engine=engine, scope_validator=scope)

    result = await recon_orch.execute_reconnaissance(
        campaign_id="safety-test-001",
        target_domain="https://unauthorized-victim.com",
        seed_assets=["https://unauthorized-victim.com/api"],
        enable_subdomain_discovery=False,
    )

    # 1. Scope Gating Assertions
    assert len(result.assets_in_scope) == 0
    assert len(result.assets_out_of_scope) >= 1
    assert result.assets_out_of_scope[0].scope_status == "OUT_OF_SCOPE"

    # 2. Hard Zero Network Calls Invariant
    assert len(transport.calls) == 0
    assert result.recon_requests_used == 0


@pytest.mark.asyncio
async def test_redirect_to_out_of_scope_is_blocked():
    """Verify that a redirect chain exiting scope is blocked at the boundary."""
    scope = ScopeValidator(
        in_scope_assets=["https://authorized.com"],
        out_of_scope_assets=["https://evil-attacker.com"],
    )
    transport = MockTransport(
        default_status=302,
        default_headers={"Location": "https://evil-attacker.com/steal-creds"},
        default_body=b"",
    )
    engine = RequestEngine(scope_validator=scope, transport=transport)

    probe_engine = HttpProbeEngine(request_engine=engine, scope_validator=scope)
    asset = DiscoveredAsset(
        asset_id="asset-redirect",
        raw_asset="https://authorized.com/login",
        canonical_url="https://authorized.com/login",
        hostname="authorized.com",
        scheme="https",
        port=443,
        path="/login",
        asset_type="WEB_APPLICATION",
        source=DiscoverySource.USER_INPUT,
        scope_status="IN_SCOPE",
    )

    probe_res = await probe_engine.probe_asset(asset)

    assert probe_res.is_redirect is True
    assert len(probe_res.redirect_chain) == 1
    assert probe_res.redirect_chain[0]["scope_allowed"] is False
    assert "exits" in probe_res.redirect_chain[0]["block_reason"].lower()

    # The probe only fetched in-scope URLs (login and soft-404 probe), NEVER the out-of-scope destination
    assert len(transport.calls) == 2
    assert all("evil-attacker.com" not in call["url"] for call in transport.calls)
    assert transport.calls[0]["url"] == "https://authorized.com/login"


@pytest.mark.asyncio
async def test_malformed_xml_html_and_json_error_resilience():
    """Ensure malformed markup or corrupted formats do not crash the recon pipeline."""
    scope = ScopeValidator(in_scope_assets=["https://example.com"])
    transport = MockTransport(
        default_status=200,
        default_headers={"Content-Type": "text/html"},
        default_body=b"<<<<malformed XML / HTML >>>>>",
    )
    engine = RequestEngine(scope_validator=scope, transport=transport)
    recon_orch = ReconOrchestrator(request_engine=engine, scope_validator=scope)

    # Should execute smoothly without raising parser exceptions
    result = await recon_orch.execute_reconnaissance(
        campaign_id="resilience-test",
        target_domain="https://example.com",
        enable_subdomain_discovery=False,
    )
    assert len(result.assets_in_scope) == 1


@pytest.mark.asyncio
async def test_llm_hallucinated_asset_cannot_override_scope():
    """Ensure that an unverified / LLM-suggested asset cannot bypass ScopeValidator."""
    scope = ScopeValidator(
        in_scope_assets=["https://app.target.com"],
        out_of_scope_assets=["https://internal.target.com"],
    )

    asset_engine = AssetDiscoveryEngine(scope_validator=scope)
    in_scope, out_of_scope, safety_events = await asset_engine.discover_assets(
        target="https://app.target.com",
        seed_assets=["https://internal.target.com", "https://malicious-domain.com"],
        enable_subdomain_discovery=False,
    )

    in_scope_urls = [a.canonical_url for a in in_scope]
    assert "https://app.target.com/" in in_scope_urls
    assert "https://internal.target.com/" not in in_scope_urls
    assert "https://malicious-domain.com/" not in in_scope_urls
    assert len(out_of_scope) == 2
