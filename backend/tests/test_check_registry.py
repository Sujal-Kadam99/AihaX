"""Unit & integration tests for Check Registry and Phase 4 checks."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from typing import Any, Dict, Optional
from pydantic import ValidationError

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    EvidenceContract,
    Severity,
    CheckRegistry,
    registry,
)
from backend.core.scope_validator import ScopeValidator
from backend.services.request_engine import (
    MockTransport,
    RequestEngine,
    RequestEvidence,
    RequestSpec,
)
import backend.agents.checks  # Load all 7 checks into global registry


@pytest.fixture
def test_registry():
    return CheckRegistry()


class DummyCheck(BaseCheck):
    contract = CheckContract(
        id="DUMMY_001",
        name="Dummy Check",
        category=CheckCategory.RECON,
        description="A dummy check for testing",
        severity=Severity.INFO,
        vulnerability_type="Reconnaissance",
        security_property="Dummy property",
        verification_strategy="generic_reproducibility",
    )

    async def execute(self, request_engine: Any, target_url: str, config: Dict[str, Any]) -> Optional[CheckResult]:
        return CheckResult(
            check_id=self.contract.id,
            title=self.contract.name,
            target=target_url,
            affected_url=target_url,
            vulnerability_type=self.contract.vulnerability_type,
            severity=self.contract.severity,
            candidate_reason="Dummy candidate reason",
            confidence=100,
        )


def test_registry_register_and_retrieve(test_registry):
    test_registry.register(DummyCheck)
    check_class = test_registry.get_check("DUMMY_001")
    assert check_class == DummyCheck

    checks = test_registry.list_checks()
    assert len(checks) == 1
    assert checks[0].id == "DUMMY_001"


def test_registry_duplicate_registration(test_registry):
    test_registry.register(DummyCheck)
    with pytest.raises(ValueError, match="already registered"):
        test_registry.register(DummyCheck)


def test_registry_invalid_contract():
    with pytest.raises(ValidationError):
        CheckContract(
            id="INVALID",
            name="Invalid",
            category="invalid_category",  # type: ignore
            description="Bad",
            severity="info",  # type: ignore
        )


def test_registry_not_found(test_registry):
    with pytest.raises(KeyError, match="not found"):
        test_registry.get_check("NON_EXISTENT")


def test_get_checks_by_category(test_registry):
    test_registry.register(DummyCheck)
    recon_checks = test_registry.get_checks_by_category(CheckCategory.RECON)
    assert len(recon_checks) == 1
    auth_checks = test_registry.get_checks_by_category(CheckCategory.AUTH)
    assert len(auth_checks) == 0


def test_all_7_phase4_checks_registered():
    """Requirement 1 & 2: All Phase 4 checks register with complete metadata."""
    expected_ids = [
        "C001_Open_Port_80",
        "C002_Missing_Security_Headers",
        "C003_Sensitive_Files_Exposure",
        "C004_CORS_Misconfiguration",
        "C005_GraphQL_Introspection",
        "C006_Directory_Listing",
        "C007_Open_Redirect",
    ]

    for check_id in expected_ids:
        check_cls = registry.get_check(check_id)
        assert check_cls is not None
        contract = check_cls.contract
        assert contract.id == check_id
        assert contract.name
        assert contract.description
        assert contract.vulnerability_type
        assert contract.cwe
        assert contract.owasp_category
        assert contract.security_property
        assert contract.remediation_guidance
        assert len(contract.references) > 0
        assert contract.verification_strategy is not None
        assert len(contract.required_evidence) > 0
        assert contract.destructive is False


@pytest.mark.asyncio
async def test_c001_open_port_check_with_request_engine():
    """Test C001 Open Port / HTTP Exposure check candidate detection."""
    from backend.agents.checks.c001_open_port_80 import C001OpenPort80

    mock_transport = MockTransport(default_status=200, default_headers={"Server": "nginx"})
    validator = ScopeValidator(in_scope_assets=["http://app.target.com"])
    request_engine = RequestEngine(scope_validator=validator, transport=mock_transport)

    check = C001OpenPort80()
    result = await check.execute(request_engine, "http://app.target.com", {})

    assert result is not None
    assert result.check_id == "C001_Open_Port_80"
    assert result.verification_status == "CANDIDATE"
    assert len(result.request_ids) > 0
    assert len(result.evidence_ids) > 0
    assert mock_transport.call_count == 1


@pytest.mark.asyncio
async def test_c002_missing_security_headers_check():
    """Test C002 Missing Security Headers candidate detection."""
    from backend.agents.checks.c002_missing_security_headers import C002MissingSecurityHeaders

    # Return response lacking HSTS, CSP, X-Frame-Options
    mock_transport = MockTransport(default_status=200, default_headers={"Server": "nginx"})
    validator = ScopeValidator(in_scope_assets=["https://app.target.com"])
    request_engine = RequestEngine(scope_validator=validator, transport=mock_transport)

    check = C002MissingSecurityHeaders()
    result = await check.execute(request_engine, "https://app.target.com", {})

    assert result is not None
    assert result.check_id == "C002_Missing_Security_Headers"
    assert result.verification_status == "CANDIDATE"
    assert "strict-transport-security" in result.observed_data["missing_headers"]


@pytest.mark.asyncio
async def test_c003_sensitive_files_exposure_check():
    """Test C003 Sensitive Files Exposure candidate detection."""
    from backend.agents.checks.c003_sensitive_files_exposure import C003SensitiveFilesExposure

    mock_transport = MockTransport()
    # Route /.env to 200 with DB_PASSWORD
    mock_transport.add_route(
        "https://app.target.com/.env",
        status=200,
        body="DB_HOST=localhost\nDB_PASSWORD=supersecret\nSECRET_KEY=abcd",
    )
    validator = ScopeValidator(in_scope_assets=["https://app.target.com"])
    request_engine = RequestEngine(scope_validator=validator, transport=mock_transport)

    check = C003SensitiveFilesExposure()
    result = await check.execute(request_engine, "https://app.target.com", {})

    assert result is not None
    assert result.check_id == "C003_Sensitive_Files_Exposure"
    assert result.verification_status == "CANDIDATE"
    assert result.observed_data["matched_keyword"] in ["DB_", "SECRET", "PASSWORD"]


@pytest.mark.asyncio
async def test_c004_cors_misconfiguration_check():
    """Test C004 CORS Misconfiguration candidate detection."""
    from backend.agents.checks.c004_cors_misconfiguration import C004CORSMisconfiguration

    mock_transport = MockTransport(
        default_status=200,
        default_headers={
            "Access-Control-Allow-Origin": "https://evil.com",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    validator = ScopeValidator(in_scope_assets=["https://app.target.com"])
    request_engine = RequestEngine(scope_validator=validator, transport=mock_transport)

    check = C004CORSMisconfiguration()
    result = await check.execute(request_engine, "https://app.target.com", {})

    assert result is not None
    assert result.check_id == "C004_CORS_Misconfiguration"
    assert result.verification_status == "CANDIDATE"
    assert result.observed_data["access_control_allow_credentials"] is True


@pytest.mark.asyncio
async def test_c005_graphql_introspection_check():
    """Test C005 GraphQL Introspection candidate detection."""
    from backend.agents.checks.c005_graphql_introspection import C005GraphQLIntrospection

    mock_transport = MockTransport()
    mock_transport.add_route(
        "https://app.target.com/graphql",
        status=200,
        body='{"data":{"__schema":{"types":[{"name":"User"},{"name":"Query"}]}}}',
    )
    validator = ScopeValidator(in_scope_assets=["https://app.target.com"])
    request_engine = RequestEngine(scope_validator=validator, transport=mock_transport)

    check = C005GraphQLIntrospection()
    result = await check.execute(request_engine, "https://app.target.com", {})

    assert result is not None
    assert result.check_id == "C005_GraphQL_Introspection"
    assert result.verification_status == "CANDIDATE"
    assert result.observed_data["introspection_successful"] is True


@pytest.mark.asyncio
async def test_c006_directory_listing_check():
    """Test C006 Directory Listing candidate detection."""
    from backend.agents.checks.c006_directory_listing import C006DirectoryListing

    mock_transport = MockTransport()
    mock_transport.add_route(
        "https://app.target.com/images/",
        status=200,
        body="<html><head><title>Index of /images/</title></head><body><h1>Index of /images/</h1></body></html>",
    )
    validator = ScopeValidator(in_scope_assets=["https://app.target.com"])
    request_engine = RequestEngine(scope_validator=validator, transport=mock_transport)

    check = C006DirectoryListing()
    result = await check.execute(request_engine, "https://app.target.com", {})

    assert result is not None
    assert result.check_id == "C006_Directory_Listing"
    assert result.verification_status == "CANDIDATE"
    assert "Index of" in result.observed_data["matched_indicator"]


@pytest.mark.asyncio
async def test_c007_open_redirect_check():
    """Test C007 Open Redirect candidate detection."""
    from backend.agents.checks.c007_open_redirect import C007OpenRedirect

    mock_transport = MockTransport()
    mock_transport.add_route(
        "https://app.target.com?next=https://evil.com",
        status=302,
        headers={"Location": "https://evil.com/login"},
    )
    validator = ScopeValidator(in_scope_assets=["https://app.target.com"])
    request_engine = RequestEngine(scope_validator=validator, transport=mock_transport)

    check = C007OpenRedirect()
    result = await check.execute(request_engine, "https://app.target.com", {})

    assert result is not None
    assert result.check_id == "C007_Open_Redirect"
    assert result.verification_status == "CANDIDATE"
    assert result.observed_data["location_header"] == "https://evil.com/login"


@pytest.mark.asyncio
async def test_out_of_scope_target_produces_zero_transport_calls():
    """Requirement 6: Out-of-scope target produces zero transport calls."""
    from backend.agents.checks.c002_missing_security_headers import C002MissingSecurityHeaders

    mock_transport = MockTransport(default_status=200)
    # ScopeValidator allows only app.target.com
    validator = ScopeValidator(in_scope_assets=["https://app.target.com"])
    request_engine = RequestEngine(scope_validator=validator, transport=mock_transport)

    check = C002MissingSecurityHeaders()
    # Execute against out-of-scope target
    result = await check.execute(request_engine, "https://unauthorized-victim.com", {})

    assert result is None
    # ZERO transport calls must have been made to mock_transport!
    assert mock_transport.call_count == 0


@pytest.mark.asyncio
async def test_unauthorized_target_produces_zero_transport_calls():
    """Requirement 7: Authorization failure produces zero transport calls."""
    from backend.agents.checks.c001_open_port_80 import C001OpenPort80

    mock_transport = MockTransport(default_status=200)
    validator = ScopeValidator(in_scope_assets=["http://app.target.com"])
    request_engine = RequestEngine(scope_validator=validator, transport=mock_transport)

    # If spec has authorization_confirmed=False
    spec = RequestSpec(url="http://app.target.com", authorization_confirmed=False)
    evidence = await request_engine.execute(spec)

    assert evidence.success is False
    assert evidence.transport_error["error_type"] in ("AUTH_MISSING", "UNAUTHORIZED_TARGET")
    assert mock_transport.call_count == 0
