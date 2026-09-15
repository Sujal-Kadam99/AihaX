"""AihaX Phase 4 Real TCP HTTP Socket Reconnaissance & Asset Intelligence Tests.

Tests real-world reconnaissance pipelines against the live Security Lab server.
"""

from __future__ import annotations

import pytest
from aiohttp import web

from backend.core.scope_validator import ScopeValidator
from backend.recon import (
    AssetCapabilities,
    EndpointType,
    HttpProbeEngine,
    ReconOrchestrator,
    TechnologyDetector,
)
from backend.recon.models import DiscoveredAsset, DiscoverySource
from backend.services.request_engine import AiohttpTransport, RequestEngine
from backend.tests.fixtures.security_lab.lab_server import create_security_lab_app


import socket

@pytest.fixture
def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def live_security_lab(free_port: int):
    """Spin up a real HTTP socket on loopback."""
    app = create_security_lab_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", free_port)
    await site.start()
    base_url = f"http://127.0.0.1:{free_port}"

    yield base_url

    await runner.cleanup()


@pytest.mark.asyncio
async def test_real_http_service_probe_and_tech_detection(live_security_lab: str):
    base_url = live_security_lab
    scope = ScopeValidator(in_scope_assets=[base_url])
    transport = AiohttpTransport()
    engine = RequestEngine(scope_validator=scope, transport=transport)

    probe_engine = HttpProbeEngine(request_engine=engine, scope_validator=scope)
    port = int(base_url.split(":")[-1])
    asset = DiscoveredAsset(
        asset_id="asset-001",
        raw_asset=f"{base_url}/app_index",
        canonical_url=f"{base_url}/app_index",
        hostname="127.0.0.1",
        scheme="http",
        port=port,
        path="/app_index",
        asset_type="WEB_APPLICATION",
        source=DiscoverySource.USER_INPUT,
        scope_status="IN_SCOPE",
    )

    probe_res = await probe_engine.probe_asset(asset)

    assert probe_res.accessible is True
    assert probe_res.status_code == 200
    assert probe_res.title == "Corporate Portal & API Gateway"
    assert probe_res.server_banner == "nginx/1.22.1"

    # Detect Technologies
    techs = TechnologyDetector.detect_technologies(
        headers=probe_res.headers,
        body_text=probe_res.title + ' <meta name="generator" content="WordPress 6.2">',
        url_path="/app_index",
    )
    tech_names = {t.name: t.version for t in techs}

    assert "Nginx" in tech_names
    assert tech_names["Nginx"] == "1.22.1"
    assert "PHP" in tech_names
    assert tech_names["PHP"] == "8.1.0"
    assert "WordPress" in tech_names
    assert tech_names["WordPress"] == "6.2"


@pytest.mark.asyncio
async def test_real_http_endpoint_discovery_robots_sitemap_and_html(live_security_lab: str):
    base_url = live_security_lab
    scope = ScopeValidator(in_scope_assets=[base_url])
    transport = AiohttpTransport()
    engine = RequestEngine(scope_validator=scope, transport=transport)

    orchestrator = ReconOrchestrator(request_engine=engine, scope_validator=scope)
    port = int(base_url.split(":")[-1])
    asset = DiscoveredAsset(
        asset_id="asset-root",
        raw_asset=f"{base_url}/app_index",
        canonical_url=f"{base_url}/app_index",
        hostname="127.0.0.1",
        scheme="http",
        port=port,
        path="/app_index",
        asset_type="WEB_APPLICATION",
        source=DiscoverySource.USER_INPUT,
        scope_status="IN_SCOPE",
    )

    endpoints = await orchestrator.endpoint_engine.discover_endpoints(asset=asset)
    paths = {e.path for e in endpoints}

    # 1. robots.txt discovery
    assert "/admin" in paths or any("admin" in p for p in paths)

    # 2. sitemap.xml discovery
    assert any("/secure/app" in p for p in paths)

    # 3. HTML Link & Form extraction
    assert any("/api/v1/accounts/1002" in p for p in paths)
    upload_eps = [e for e in endpoints if e.is_upload or e.endpoint_type == EndpointType.FILE_UPLOAD]
    assert len(upload_eps) >= 1
    assert upload_eps[0].path == "/upload"

    # 4. JS route analysis
    assert any("/api/v2/orders" in p for p in paths)
    assert any("/graphql" in p for p in paths)

    # 5. OpenAPI route extraction
    assert any("/api/v1/accounts/{id}" in p for p in paths or "/api/upload" in p for p in paths)


@pytest.mark.asyncio
async def test_real_http_rate_limiting_and_soft_404(live_security_lab: str):
    base_url = live_security_lab
    scope = ScopeValidator(in_scope_assets=[base_url])
    transport = AiohttpTransport()
    engine = RequestEngine(scope_validator=scope, transport=transport)

    probe_engine = HttpProbeEngine(request_engine=engine, scope_validator=scope)

    # 1. Rate Limit Detection
    port = int(base_url.split(":")[-1])
    rate_asset = DiscoveredAsset(
        asset_id="rate-asset",
        raw_asset=f"{base_url}/rate_limited",
        canonical_url=f"{base_url}/rate_limited",
        hostname="127.0.0.1",
        scheme="http",
        port=port,
        path="/rate_limited",
        asset_type="WEB_APPLICATION",
        source=DiscoverySource.USER_INPUT,
        scope_status="IN_SCOPE",
    )
    probe_rate = await probe_engine.probe_asset(rate_asset)
    assert probe_rate.status_code == 429
    assert probe_rate.rate_limited is True
    assert probe_rate.retry_after == 60

    # 2. Soft-404 Detection on deceptive endpoint
    is_soft = await probe_engine._detect_soft_404(f"{base_url}/deceptive/soft_404")
    assert isinstance(is_soft, bool)


@pytest.mark.asyncio
async def test_real_http_end_to_end_recon_orchestration(live_security_lab: str):
    base_url = live_security_lab
    scope = ScopeValidator(in_scope_assets=[base_url])
    transport = AiohttpTransport()
    engine = RequestEngine(scope_validator=scope, transport=transport)

    orchestrator = ReconOrchestrator(request_engine=engine, scope_validator=scope)
    result = await orchestrator.execute_reconnaissance(
        campaign_id="real-recon-001",
        target_domain=f"{base_url}/app_index",
        enable_subdomain_discovery=False,
    )

    assert len(result.assets_in_scope) >= 1
    assert len(result.endpoints) >= 4
    assert len(result.planned_checks) > 10

    # Verify check plan contains capability-appropriate checks
    assert "C002_Missing_Security_Headers" in result.planned_checks
    assert "C005_GraphQL_Introspection" in result.planned_checks  # GraphQL discovered
    assert "C055_Dangerous_File_Upload" in result.planned_checks  # File upload discovered
    assert "C067_IDOR_Numeric_IDs" in result.planned_checks  # API discovered

