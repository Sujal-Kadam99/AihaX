"""Integration tests for Campaign Execution Orchestrator with Security Lab."""

import pytest
import aiohttp
from aiohttp import web
from backend.core.scope_validator import ScopeValidator
from backend.services.campaign_executor import (
    AssetNormalizer,
    CampaignExecutor,
    Capability,
    CheckPlanStatus,
    CheckPlanner,
)
from backend.services.request_engine import (
    AiohttpTransport,
    AuthenticationContext,
    MockTransport,
    RawResponse,
)
from backend.tests.fixtures.security_lab.lab_server import create_security_lab_app


@pytest.fixture
async def live_security_lab(unused_tcp_port):
    """Run an ephemeral, live TCP HTTP security lab instance for integration tests."""
    port = unused_tcp_port
    app = create_security_lab_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()

    base_url = f"http://127.0.0.1:{port}"
    yield base_url

    await runner.cleanup()


@pytest.mark.asyncio
async def test_check_planner_capability_and_prerequisite_filtering():
    target = AssetNormalizer.normalize("http://127.0.0.1:8000")

    # 1. HTTP capability only, no auth
    plan_http = CheckPlanner.create_plan(
        campaign_id="plan-test-1",
        target=target,
        capabilities={Capability.HTTP},
        selected_checks=[
            "C003_Sensitive_Files_Exposure",
            "C039_DOM_XSS_Indicators",     # Requires BROWSER
            "C067_IDOR_Numeric_IDs",       # Requires AUTH
            "C075_Race_Condition",         # Requires WORKFLOW
        ],
    )

    statuses = {c.check_id: c.status for c in plan_http.planned_checks}
    assert statuses["C003_Sensitive_Files_Exposure"] == CheckPlanStatus.PLANNED
    assert statuses["C039_DOM_XSS_Indicators"] == CheckPlanStatus.PREREQUISITE_MISSING
    assert statuses["C067_IDOR_Numeric_IDs"] == CheckPlanStatus.PREREQUISITE_MISSING
    assert statuses["C075_Race_Condition"] == CheckPlanStatus.PREREQUISITE_MISSING

    # 2. Add Auth & Browser capabilities
    auth_ctx = AuthenticationContext(name="user_a", headers={"Authorization": "Bearer valid_jwt_token"})
    plan_full = CheckPlanner.create_plan(
        campaign_id="plan-test-2",
        target=target,
        capabilities={Capability.HTTP, Capability.BROWSER, Capability.WORKFLOW},
        auth_contexts={"user_a": auth_ctx},
        selected_checks=[
            "C039_DOM_XSS_Indicators",
            "C067_IDOR_Numeric_IDs",
            "C075_Race_Condition",
        ],
    )

    statuses_full = {c.check_id: c.status for c in plan_full.planned_checks}
    assert statuses_full["C039_DOM_XSS_Indicators"] == CheckPlanStatus.PLANNED
    assert statuses_full["C067_IDOR_Numeric_IDs"] == CheckPlanStatus.PLANNED
    assert statuses_full["C075_Race_Condition"] == CheckPlanStatus.PLANNED


@pytest.mark.asyncio
async def test_end_to_end_controlled_campaign_execution(live_security_lab):
    base_url = live_security_lab

    # Set up scope validator with local lab in-scope and an out-of-scope victim
    scope = ScopeValidator(
        in_scope_assets=[base_url],
        out_of_scope_assets=["http://unauthorized-victim.local"],
    )

    # Use genuine AiohttpTransport over loopback TCP sockets
    transport = AiohttpTransport()
    executor = CampaignExecutor(
        scope_validator=scope,
        transport=transport,
        campaign_budget=50,
        target_budget=50,
        check_budget=20,
    )

    # Execute complete campaign testing multiple checks and assets
    result = await executor.execute_campaign(
        campaign_id="e2e-campaign-proof-001",
        target_url=base_url,
        discovered_assets=[
            f"{base_url}/vulnerable/c003_env",
            f"{base_url}/deceptive/c003_soft404",
            "http://unauthorized-victim.local/api",  # Out of scope
        ],
        selected_checks=[
            "C003_Sensitive_Files_Exposure",
            "C002_Missing_Security_Headers",
        ],
    )

    # 1. Scope & Asset Assertions
    assert result.assets_discovered == 4
    assert result.assets_scanned == 3  # base_url and subpaths within base_url
    assert result.assets_skipped == 1  # unauthorized-victim.local

    # 2. Verification Assertions
    assert result.verified_findings_count >= 1
    assert result.requests_used > 0
    assert result.requests_used <= result.requests_budget

    # 3. Deduplication & Reporting Assertions
    assert len(result.deduplicated_groups) >= 1
    assert len(result.reports) >= 1
    for r in result.reports:
        assert r.proof_of_concept.request != ""
        assert r.severity in ["critical", "high", "medium", "low", "info"]

    # 4. Audit Trail Assertions
    assert len(result.audit_trail) >= 5
    assert len(result.safety_events) >= 1  # Logged the out-of-scope asset skip
