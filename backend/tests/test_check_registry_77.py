"""Comprehensive unit & integration test suite verifying all 77 checks in AihaX CheckRegistry."""

import pytest
import asyncio
from backend.core.check_registry import (
    CheckCategory,
    CheckContract,
    CheckRegistry,
    BaseCheck,
    Severity,
    registry,
)
import backend.agents.checks  # Trigger registration
from backend.core.scope_validator import ScopeValidator
from backend.services.request_engine import (
    MockTransport,
    RequestEngine,
)
from backend.services.verification_engine import VerificationRegistry


def _get_production_checks():
    return [c for c in registry.get_all_checks() if not c.contract.id.startswith("C999")]


def test_exact_86_checks_registered():
    """Verify that exactly 86 production security checks are registered."""
    prod_checks = _get_production_checks()
    assert len(prod_checks) == 86, f"Expected 86 checks registered, got {len(prod_checks)}"


def test_all_86_check_ids_sequential():
    """Verify check IDs span sequentially from C001 to C086."""
    prod_checks = _get_production_checks()
    check_ids = sorted([c.contract.id for c in prod_checks])

    for i in range(1, 87):
        expected_prefix = f"C{i:03d}_"
        matching = [cid for cid in check_ids if cid.startswith(expected_prefix)]
        assert len(matching) == 1, f"Missing or duplicate check for prefix {expected_prefix}: {matching}"


def test_all_86_contracts_valid():
    """Verify all contracts have non-empty metadata fields."""
    prod_checks = _get_production_checks()
    for check_cls in prod_checks:
        contract = check_cls.contract
        check_id = contract.id
        assert isinstance(contract, CheckContract), f"{check_id} contract is not CheckContract"
        assert contract.id == check_id, f"{check_id} id mismatch"
        assert contract.name, f"{check_id} missing name"
        assert contract.category in CheckCategory, f"{check_id} invalid category {contract.category}"
        assert contract.severity in Severity, f"{check_id} invalid severity {contract.severity}"
        assert contract.vulnerability_type, f"{check_id} missing vulnerability_type"
        assert contract.cwe.startswith("CWE-") or "CWE-" in contract.cwe, f"{check_id} invalid CWE {contract.cwe}"
        assert contract.owasp_category, f"{check_id} missing owasp_category"
        assert contract.remediation_guidance, f"{check_id} missing remediation_guidance"
        assert len(contract.references) >= 1, f"{check_id} missing references"
        assert contract.verification_strategy, f"{check_id} missing verification_strategy"
        assert isinstance(contract.required_evidence, list), f"{check_id} missing required_evidence"


def test_all_categories_populated():
    """Verify all vulnerability categories contain their expected check counts."""
    prod_checks = _get_production_checks()
    counts = {cat: len([c for c in prod_checks if c.contract.category == cat]) for cat in CheckCategory}

    assert counts[CheckCategory.RECON] == 11, f"Expected 11 RECON checks, got {counts[CheckCategory.RECON]}"
    assert counts[CheckCategory.AUTH] == 15, f"Expected 15 AUTH checks, got {counts[CheckCategory.AUTH]}"
    assert counts[CheckCategory.INJECTION] == 16, f"Expected 16 INJECTION checks, got {counts[CheckCategory.INJECTION]}"
    assert counts[CheckCategory.XSS] == 10, f"Expected 10 XSS checks, got {counts[CheckCategory.XSS]}"
    assert counts[CheckCategory.MISCONFIG] == 11, f"Expected 11 MISCONFIG checks, got {counts[CheckCategory.MISCONFIG]}"
    assert counts[CheckCategory.SENSITIVE_DATA] == 10, f"Expected 10 SENSITIVE_DATA checks, got {counts[CheckCategory.SENSITIVE_DATA]}"
    assert counts[CheckCategory.BUSINESS_LOGIC] == 11, f"Expected 11 BUSINESS_LOGIC checks, got {counts[CheckCategory.BUSINESS_LOGIC]}"
    assert counts[CheckCategory.INFRASTRUCTURE] == 2, f"Expected 2 INFRASTRUCTURE checks, got {counts[CheckCategory.INFRASTRUCTURE]}"


def test_verification_strategy_mapping_completeness():
    """Verify every registered check has a resolvable verification strategy."""
    prod_checks = _get_production_checks()
    for check_cls in prod_checks:
        check_id = check_cls.contract.id
        strategy_name = check_cls.contract.verification_strategy
        strategy_instance = VerificationRegistry.get_strategy(strategy_name) or VerificationRegistry.get_strategy(check_id)
        assert strategy_instance is not None, f"No verification strategy found for check {check_id} (strategy name: {strategy_name})"


@pytest.mark.asyncio
async def test_c008_subdomain_takeover_mock_execution():
    """Verify C008 detection with MockTransport."""
    mock_transport = MockTransport()
    mock_transport.add_route("http://testphp.vulnweb.com/", status=200, body="<html>NoSuchBucket</html>")
    scope = ScopeValidator(in_scope_assets=["http://testphp.vulnweb.com"])
    engine = RequestEngine(scope_validator=scope, transport=mock_transport)

    check_cls = registry.get_check("C008_Subdomain_Takeover")
    assert check_cls is not None
    check = check_cls()
    result = await check.execute(engine, "http://testphp.vulnweb.com/", {})
    assert result is not None
    assert result.check_id == "C008_Subdomain_Takeover"
    assert result.verification_status == "CANDIDATE"


@pytest.mark.asyncio
async def test_c023_sql_injection_mock_execution():
    """Verify C023 detection with MockTransport."""
    mock_transport = MockTransport()
    mock_transport.add_route(
        "http://testphp.vulnweb.com/listproducts.php?id=%27",
        status=200,
        body="Error: You have an error in your SQL syntax near '' at line 1",
    )
    scope = ScopeValidator(in_scope_assets=["http://testphp.vulnweb.com"])
    engine = RequestEngine(scope_validator=scope, transport=mock_transport)

    check_cls = registry.get_check("C023_SQL_Injection")
    assert check_cls is not None
    check = check_cls()
    result = await check.execute(engine, "http://testphp.vulnweb.com/listproducts.php?id=1", {})
    assert result is not None
    assert result.check_id == "C023_SQL_Injection"
    assert "MySQL" in result.title


@pytest.mark.asyncio
async def test_c037_reflected_xss_mock_execution():
    """Verify C037 detection with MockTransport."""
    mock_transport = MockTransport()
    mock_transport.add_route(
        "http://testphp.vulnweb.com/search.php?q=%3Caihax-xss-canary-777%3E",
        status=200,
        headers={"Content-Type": "text/html"},
        body="<html><body>Search results for: <aihax-xss-canary-777></body></html>",
    )
    scope = ScopeValidator(in_scope_assets=["http://testphp.vulnweb.com"])
    engine = RequestEngine(scope_validator=scope, transport=mock_transport)

    check_cls = registry.get_check("C037_Reflected_XSS")
    assert check_cls is not None
    check = check_cls()
    result = await check.execute(engine, "http://testphp.vulnweb.com/search.php?q=test", {})
    assert result is not None
    assert result.check_id == "C037_Reflected_XSS"
    assert result.severity == Severity.HIGH
