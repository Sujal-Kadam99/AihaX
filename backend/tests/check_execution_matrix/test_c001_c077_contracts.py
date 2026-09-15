"""Execution Contract and Prerequisite Matrix Tests for all 77 checks (C001-C077)."""

import pytest

import backend.agents.checks
from backend.core.check_registry import CheckContract, registry
from backend.execution.execution_context import (
    ExecutionContext,
    ExecutionPhase,
    PrerequisiteStatus,
)
from backend.execution.parameter_model import (
    DiscoveredParameter,
    ParameterLocation,
    ParameterSource,
    ParameterType,
)
from backend.recon.models import (
    AssetCapabilities,
    AssetType,
    DiscoveredAsset,
    DiscoveredEndpoint,
    DiscoverySource,
    EndpointType,
)
from backend.services.campaign_executor import CampaignRequestBudget
from backend.services.request_engine import AuthenticationContext, ScopeValidator


def test_all_77_contracts_valid_and_non_destructive():
    contracts = registry.list_checks()
    assert len(contracts) == 77, f"Expected exactly 77 check contracts, got {len(contracts)}"

    for c in contracts:
        assert isinstance(c, CheckContract)
        assert c.validate_contract() is True
        assert c.destructive is False
        assert c.max_requests >= 1
        assert len(c.supported_methods) >= 1
        assert len(c.required_capabilities) >= 1


def test_execution_context_prerequisite_gating():
    scope_val = ScopeValidator(in_scope_assets=["example.local"])
    budget = CampaignRequestBudget(campaign_budget=100)

    asset = DiscoveredAsset(
        asset_id="ast-1",
        raw_asset="http://example.local",
        canonical_url="http://example.local",
        hostname="example.local",
        scheme="http",
        port=80,
        path="/",
        asset_type=AssetType.WEB_APPLICATION,
        source=DiscoverySource.PROGRAM_SCOPE,
        scope_status="IN_SCOPE",
    )
    endpoint = DiscoveredEndpoint(
        endpoint_id="ep-1",
        url="http://example.local/search",
        path="/search",
        method="GET",
        endpoint_type=EndpointType.PAGE,
        source=DiscoverySource.HTML_CRAWL,
        parameters=[],
        auth_required="PUBLIC",
        content_type="text/html",
        status_code=200,
        is_api=False,
        is_graphql=False,
        is_upload=False,
        discovered_at="2026-08-28T00:00:00Z",
    )

    contract_param_req = CheckContract(
        id="C037_Reflected_XSS",
        name="Reflected XSS",
        category="xss",
        description="Reflected XSS check",
        severity="high",
        requires_parameters=True,
    )

    # 1. Missing parameter -> PREREQUISITE MISSING
    ctx_missing_param = ExecutionContext(
        campaign_id="cmp-1",
        asset=asset,
        endpoint=endpoint,
        parameter=None,
        contract=contract_param_req,
        capabilities=AssetCapabilities(http=True, https=True),
        scope_validator=scope_val,
        budget=budget,
    )
    status, reason = ctx_missing_param.evaluate_prerequisites()
    assert status == PrerequisiteStatus.MISSING_PARAMETER

    # 2. Parameter provided -> SATISFIED
    param = DiscoveredParameter(
        parameter_id="p-1",
        endpoint_url=endpoint.url,
        method="GET",
        name="q",
        location=ParameterLocation.QUERY,
        param_type=ParameterType.STRING,
        source=ParameterSource.URL_QUERY,
        provenance="Query",
    )
    ctx_satisfied = ExecutionContext(
        campaign_id="cmp-1",
        asset=asset,
        endpoint=endpoint,
        parameter=param,
        contract=contract_param_req,
        capabilities=AssetCapabilities(http=True, https=True),
        scope_validator=scope_val,
        budget=budget,
    )
    status_sat, _ = ctx_satisfied.evaluate_prerequisites()
    assert status_sat == PrerequisiteStatus.SATISFIED

    # 3. Out-of-scope endpoint -> MISSING_SCOPE
    out_ep = DiscoveredEndpoint(
        endpoint_id="ep-out",
        url="http://evil-out-of-scope.com/test",
        path="/test",
        method="GET",
        endpoint_type=EndpointType.PAGE,
        source=DiscoverySource.HTML_CRAWL,
        parameters=[],
        auth_required="PUBLIC",
        content_type="text/html",
        status_code=200,
        is_api=False,
        is_graphql=False,
        is_upload=False,
        discovered_at="2026-08-28T00:00:00Z",
    )
    ctx_out_of_scope = ExecutionContext(
        campaign_id="cmp-1",
        asset=asset,
        endpoint=out_ep,
        parameter=param,
        contract=contract_param_req,
        capabilities=AssetCapabilities(http=True, https=True),
        scope_validator=scope_val,
        budget=budget,
    )
    status_scope, _ = ctx_out_of_scope.evaluate_prerequisites()
    assert status_scope == PrerequisiteStatus.MISSING_SCOPE


def test_auth_required_check_prerequisite_gating():
    scope_val = ScopeValidator(in_scope_assets=["example.local"])
    budget = CampaignRequestBudget(campaign_budget=100)

    asset = DiscoveredAsset(
        asset_id="ast-1",
        raw_asset="http://example.local",
        canonical_url="http://example.local",
        hostname="example.local",
        scheme="http",
        port=80,
        path="/",
        asset_type=AssetType.WEB_APPLICATION,
        source=DiscoverySource.PROGRAM_SCOPE,
        scope_status="IN_SCOPE",
    )
    endpoint = DiscoveredEndpoint(
        endpoint_id="ep-1",
        url="http://example.local/api/v1/admin/users",
        path="/api/v1/admin/users",
        method="GET",
        endpoint_type=EndpointType.API,
        source=DiscoverySource.OPENAPI_SPEC,
        parameters=[],
        auth_required="AUTHENTICATION_REQUIRED",
        content_type="application/json",
        status_code=401,
        is_api=True,
        is_graphql=False,
        is_upload=False,
        discovered_at="2026-08-28T00:00:00Z",
    )

    contract_auth_req = CheckContract(
        id="C071_Privilege_Escalation",
        name="Privilege Escalation",
        category="auth",
        description="Privilege escalation check",
        severity="high",
        requires_auth=True,
    )

    # Without auth context -> MISSING_AUTH
    ctx_no_auth = ExecutionContext(
        campaign_id="cmp-1",
        asset=asset,
        endpoint=endpoint,
        parameter=None,
        contract=contract_auth_req,
        capabilities=AssetCapabilities(http=True, https=True),
        scope_validator=scope_val,
        budget=budget,
        auth_context=None,
    )
    status, _ = ctx_no_auth.evaluate_prerequisites()
    assert status == PrerequisiteStatus.MISSING_AUTH

    # With auth context -> SATISFIED
    auth_ctx = AuthenticationContext(name="admin_user", headers={"Authorization": "Bearer test-token"})
    ctx_with_auth = ExecutionContext(
        campaign_id="cmp-1",
        asset=asset,
        endpoint=endpoint,
        parameter=None,
        contract=contract_auth_req,
        capabilities=AssetCapabilities(http=True, https=True),
        scope_validator=scope_val,
        budget=budget,
        auth_context=auth_ctx,
    )
    status_with_auth, _ = ctx_with_auth.evaluate_prerequisites()
    assert status_with_auth == PrerequisiteStatus.SATISFIED
