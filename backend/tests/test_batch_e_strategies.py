"""Unit tests for Batch E verification strategies (Groups 1-4)."""

from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock
import pytest

from backend.services.verification_engine import (
    VerificationBudget,
    VerificationConclusion,
    VerificationContext,
    VerificationReasonCode,
    VerificationRegistry,
    VerificationStatus,
)
from backend.services.request_engine import RequestEngine, RequestEvidence

# Group 1 Strategy imports
from backend.services.verification_strategies.ssrf_strategy import SsrfVerificationStrategy
from backend.services.verification_strategies.ssti_strategy import SstiVerificationStrategy
from backend.services.verification_strategies.nosql_injection_strategy import NosqlInjectionVerificationStrategy
from backend.services.verification_strategies.path_traversal_strategy import PathTraversalVerificationStrategy
from backend.services.verification_strategies.local_file_inclusion_strategy import LocalFileInclusionStrategy
from backend.services.verification_strategies.ldap_injection_strategy import LdapInjectionVerificationStrategy
from backend.services.verification_strategies.expression_language_strategy import ExpressionLanguageVerificationStrategy

# Group 2 Strategy imports
from backend.services.verification_strategies.session_fixation_strategy import SessionFixationVerificationStrategy
from backend.services.verification_strategies.password_policy_strategy import PasswordPolicyVerificationStrategy

# Group 3 Strategy imports
from backend.services.verification_strategies.cross_domain_policy_strategy import CrossDomainPolicyVerificationStrategy
from backend.services.verification_strategies.path_normalization_strategy import PathNormalizationVerificationStrategy
from backend.services.verification_strategies.comment_disclosure_strategy import CommentInformationDisclosureVerificationStrategy
from backend.services.verification_strategies.cloud_bucket_strategy import CloudBucketExposureVerificationStrategy
from backend.services.verification_strategies.cleartext_storage_strategy import CleartextStorageVerificationStrategy

# Group 4 Strategy imports
from backend.services.verification_strategies.workflow_step_skipping_strategy import WorkflowStepSkippingVerificationStrategy
from backend.services.verification_strategies.replay_attack_strategy import ReplayAttackVerificationStrategy


def make_evidence(request_id: str, response_status: int, response_body: str, response_headers: dict | None = None, success: bool = True) -> RequestEvidence:
    return RequestEvidence(
        request_id=request_id,
        timestamp="2026-09-18T00:00:00Z",
        method="GET",
        url="http://target.test",
        request_headers={},
        request_body=None,
        response_status=response_status,
        response_headers=response_headers or {},
        response_body=response_body,
        response_size=len(response_body),
        duration_ms=10.0,
        truncated=False,
        redirect_chain=[],
        scope_decision={"allowed": True},
        transport_error=None,
        request_hash="hash",
        response_hash="hash",
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


# ──────────────────────────────────────────────────────────────────────────────
# GROUP 1 TESTS
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_c036_ssrf_verified_on_proxied_robots(mock_request_engine, default_budget):
    """C036: Target fetches and proxies in-scope robots.txt -> VERIFIED."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 200, "User-agent: *\nDisallow: /admin"),
    ]
    strategy = SsrfVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-ssrf-1",
        target_url="http://target.test/proxy",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/proxy?url=http://example.com", "affected_param": "url"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.VERIFIED
    assert "Server-Side Request Forgery confirmed" in conclusion.reason_description


@pytest.mark.asyncio
async def test_c036_ssrf_false_positive_when_rejected(mock_request_engine, default_budget):
    """C036: Target rejects arbitrary URL -> NOT_REPRODUCIBLE."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 400, "Invalid URL supplied"),
        make_evidence("R2", 400, "Invalid URL supplied"),
    ]
    strategy = SsrfVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-ssrf-2",
        target_url="http://target.test/proxy",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/proxy?url=test", "affected_param": "url"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_c028_ssti_verified_on_arithmetic_computation(mock_request_engine, default_budget):
    """C028: Template expression {{31330+7}} evaluated to 31337 -> VERIFIED."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R0", 200, "Hello Guest"),
        make_evidence("R1", 200, "Hello 31337!"),
    ]
    strategy = SstiVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-ssti-1",
        target_url="http://target.test/page",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/page?name=guest", "affected_param": "name"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.VERIFIED
    assert conclusion.evidence_ids is not None


@pytest.mark.asyncio
async def test_c028_ssti_false_positive_when_reflected_literally(mock_request_engine, default_budget):
    """C028: Template expression reflected literally without evaluation -> FALSE_POSITIVE."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R0", 200, "Hello Guest"),
        make_evidence("R1", 200, "Hello {{31330+7}}!"),
        make_evidence("R2", 200, "Hello ${31330+7}!"),
        make_evidence("R3", 200, "Hello #{31330+7}!"),
        make_evidence("R4", 200, "Hello <%= 31330+7 %>!"),
        make_evidence("R5", 200, "Hello {{7*7}}!"),
    ]
    strategy = SstiVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-ssti-2",
        target_url="http://target.test/page",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/page?name=guest", "affected_param": "name"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_c025_nosql_verified_on_mongo_exception(mock_request_engine, default_budget):
    """C025: MongoDB operator discloses MongoError -> VERIFIED."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 500, "MongoError: Cast to ObjectId failed for value '$ne'"),
    ]
    strategy = NosqlInjectionVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-nosql-1",
        target_url="http://target.test/users",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/users?user=admin", "affected_param": "user"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.VERIFIED
    assert "NoSQL Injection confirmed" in conclusion.reason_description


@pytest.mark.asyncio
async def test_c025_nosql_false_positive_when_sanitized(mock_request_engine, default_budget):
    """C025: NoSQL operator sanitized and rejected cleanly -> NOT_REPRODUCIBLE."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 400, "Invalid parameter type"),
        make_evidence("R2", 400, "Invalid parameter type"),
    ]
    strategy = NosqlInjectionVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-nosql-2",
        target_url="http://target.test/users",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/users?user=admin", "affected_param": "user"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_c031_path_traversal_verified_on_passwd_file(mock_request_engine, default_budget):
    """C031: /etc/passwd contents with root:x:0:0: confirmed -> VERIFIED."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"),
    ]
    strategy = PathTraversalVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-trav-1",
        target_url="http://target.test/view",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/view?file=about.txt", "affected_param": "file"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.VERIFIED
    assert "Path Traversal confirmed" in conclusion.reason_description


@pytest.mark.asyncio
async def test_c031_path_traversal_false_positive_when_blocked(mock_request_engine, default_budget):
    """C031: Path traversal safely blocked with 403/404 -> NOT_REPRODUCIBLE."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 403, "Access Denied"),
        make_evidence("R2", 403, "Access Denied"),
        make_evidence("R3", 403, "Access Denied"),
        make_evidence("R4", 403, "Access Denied"),
    ]
    strategy = PathTraversalVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-trav-2",
        target_url="http://target.test/view",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/view?file=about.txt", "affected_param": "file"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_c032_lfi_verified_on_base64_source(mock_request_engine, default_budget):
    """C032: php://filter returns base64 encoded PHP source -> VERIFIED."""
    b64_php = base64.b64encode(b"<?php\nrequire_once 'db.php';\nfunction connect() { return true; }\n").decode("utf-8")
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 200, f"Result: {b64_php}"),
    ]
    strategy = LocalFileInclusionStrategy()

    ctx = VerificationContext(
        finding_id="f-lfi-1",
        target_url="http://target.test/index.php",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/index.php?page=home", "affected_param": "page"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.VERIFIED
    assert "Local File Inclusion confirmed" in conclusion.reason_description


@pytest.mark.asyncio
async def test_c032_lfi_false_positive_when_wrapper_ignored(mock_request_engine, default_budget):
    """C032: php://filter wrapper ignored or rejected -> NOT_REPRODUCIBLE."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 404, "Page not found"),
        make_evidence("R2", 404, "Page not found"),
        make_evidence("R3", 404, "Page not found"),
    ]
    strategy = LocalFileInclusionStrategy()

    ctx = VerificationContext(
        finding_id="f-lfi-2",
        target_url="http://target.test/index.php",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/index.php?page=home", "affected_param": "page"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_c034_ldap_verified_on_directory_exception(mock_request_engine, default_budget):
    """C034: LDAP wildcard payload causes InvalidSearchFilterException -> VERIFIED."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 500, "javax.naming.directory.InvalidSearchFilterException: Unbalanced parenthesis"),
    ]
    strategy = LdapInjectionVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-ldap-1",
        target_url="http://target.test/search",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/search?user=admin", "affected_param": "user"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.VERIFIED
    assert "LDAP Injection confirmed" in conclusion.reason_description


@pytest.mark.asyncio
async def test_c034_ldap_false_positive_when_escaped(mock_request_engine, default_budget):
    """C034: LDAP search metacharacters sanitized -> NOT_REPRODUCIBLE."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 200, "No users found"),
        make_evidence("R2", 200, "No users found"),
        make_evidence("R3", 200, "No users found"),
    ]
    strategy = LdapInjectionVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-ldap-2",
        target_url="http://target.test/search",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/search?user=admin", "affected_param": "user"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_c035_el_verified_on_spel_arithmetic(mock_request_engine, default_budget):
    """C035: Java EL expression ${31330+7} dynamically evaluates to 31337 -> VERIFIED."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R0", 200, "Welcome"),
        make_evidence("R1", 200, "Computed: 31337"),
    ]
    strategy = ExpressionLanguageVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-el-1",
        target_url="http://target.test/spel",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/spel?expr=1", "affected_param": "expr"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.VERIFIED
    assert len(conclusion.evidence_ids) > 0


@pytest.mark.asyncio
async def test_c035_el_false_positive_when_not_evaluated(mock_request_engine, default_budget):
    """C035: EL expression reflected without dynamic evaluation -> NOT_REPRODUCIBLE."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R0", 200, "Welcome"),
        make_evidence("R1", 200, "Echo: ${31330+7}"),
        make_evidence("R2", 200, "Echo: #{31330+7}"),
        make_evidence("R3", 200, "Echo: %{(31330+7)}"),
        make_evidence("R4", 200, "Echo: T(java.lang.Math).min(10,20)"),
    ]
    strategy = ExpressionLanguageVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-el-2",
        target_url="http://target.test/spel",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/spel?expr=1", "affected_param": "expr"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


# ──────────────────────────────────────────────────────────────────────────────
# GROUP 2 TESTS (Auth/Session)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_c017_session_fixation_verified_on_token_adoption(mock_request_engine, default_budget):
    """C017: Server echoes fixed token in Set-Cookie header -> VERIFIED."""
    def side_effect(spec):
        token = spec.url.split("sessionid=")[1].split("&")[0]
        return make_evidence("R1", 200, "Logged in", response_headers={"Set-Cookie": f"sessionid={token}; Path=/"})

    mock_request_engine.execute.side_effect = side_effect
    strategy = SessionFixationVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-fixation-1",
        target_url="http://target.test/login",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/login"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.VERIFIED
    assert "Server adopted client-supplied fixed session token" in conclusion.reason_description


@pytest.mark.asyncio
async def test_c017_session_fixation_false_positive_when_rejected(mock_request_engine, default_budget):
    """C017: Server issues newly generated session ID in Set-Cookie -> NOT_REPRODUCIBLE."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 200, "Logged in", response_headers={"Set-Cookie": "sessionid=fresh_server_uuid_9999; Path=/"}),
    ]
    strategy = SessionFixationVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-fixation-2",
        target_url="http://target.test/login",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/login"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_c019_password_policy_verified_on_trivial_password(mock_request_engine, default_budget):
    """C019: Registration endpoint returns 201 Created on single-character password -> VERIFIED."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 201, json.dumps({"status": "created", "user_id": 123})),
    ]
    strategy = PasswordPolicyVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-pw-1",
        target_url="http://target.test/api/register",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/api/register"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.VERIFIED
    assert "Endpoint accepted trivial password" in conclusion.reason_description


@pytest.mark.asyncio
async def test_c019_password_policy_false_positive_when_enforced(mock_request_engine, default_budget):
    """C019: Registration endpoint rejects weak password with 422 -> NOT_REPRODUCIBLE."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 422, "Password must be at least 8 characters"),
        make_evidence("R2", 422, "Password must be at least 8 characters"),
        make_evidence("R3", 422, "Password must be at least 8 characters"),
    ]
    strategy = PasswordPolicyVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-pw-2",
        target_url="http://target.test/api/register",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/api/register"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


# ──────────────────────────────────────────────────────────────────────────────
# GROUP 3 TESTS (Data Exposure/Config)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_c051_cross_domain_verified_on_wildcard_policy(mock_request_engine, default_budget):
    """C051: /crossdomain.xml served with domain="*" -> VERIFIED."""
    wildcard_xml = '<?xml version="1.0"?><cross-domain-policy><allow-access-from domain="*" /></cross-domain-policy>'
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 200, wildcard_xml),
    ]
    strategy = CrossDomainPolicyVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-cd-1",
        target_url="http://target.test/crossdomain.xml",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/crossdomain.xml"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.VERIFIED
    assert "Overly permissive cross-domain policy" in conclusion.reason_description


@pytest.mark.asyncio
async def test_c051_cross_domain_false_positive_when_not_found(mock_request_engine, default_budget):
    """C051: Policy files return 404 -> NOT_REPRODUCIBLE."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 404, "Not Found"),
        make_evidence("R2", 404, "Not Found"),
    ]
    strategy = CrossDomainPolicyVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-cd-2",
        target_url="http://target.test",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_c056_path_norm_verified_on_matrix_traversal(mock_request_engine, default_budget):
    """C056: Matrix parameter /..;/ returns HTTP 200 with admin content -> VERIFIED."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 200, "<html><body><h1>Admin Dashboard Privileged Resource</h1></body></html>"),
    ]
    strategy = PathNormalizationVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-pn-1",
        target_url="http://target.test/app",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/app"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.VERIFIED
    assert "Path normalization discrepancy verified" in conclusion.reason_description


@pytest.mark.asyncio
async def test_c056_path_norm_false_positive_when_rejected(mock_request_engine, default_budget):
    """C056: Normalization probes return 400 or 404 -> NOT_REPRODUCIBLE."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 404, "Not Found"),
        make_evidence("R2", 404, "Not Found"),
        make_evidence("R3", 404, "Not Found"),
    ]
    strategy = PathNormalizationVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-pn-2",
        target_url="http://target.test/app",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/app"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_c060_comment_disclosure_verified_on_db_password(mock_request_engine, default_budget):
    """C060: HTML contains <!-- db_pass=SuperSecret123 --> -> VERIFIED."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 200, "<html><!-- db_pass=SuperSecret123 --><body>App</body></html>"),
    ]
    strategy = CommentInformationDisclosureVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-comment-1",
        target_url="http://target.test/index.html",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/index.html"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.VERIFIED
    assert "Sensitive developer comment discovered" in conclusion.reason_description


@pytest.mark.asyncio
async def test_c060_comment_disclosure_false_positive_when_clean(mock_request_engine, default_budget):
    """C060: HTML contains no sensitive comments -> NOT_REPRODUCIBLE."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 200, "<html><!-- Copyright 2026 --><body>App</body></html>"),
    ]
    strategy = CommentInformationDisclosureVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-comment-2",
        target_url="http://target.test/index.html",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/index.html"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_c063_cloud_bucket_verified_on_list_bucket_result(mock_request_engine, default_budget):
    """C063: S3 bucket endpoint returns <ListBucketResult> XML -> VERIFIED."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R0", 200, "<html><body><script src='https://mybucket.s3.amazonaws.com/bundle.js'></script></body></html>"),
        make_evidence("R1", 200, '<?xml version="1.0"?><ListBucketResult><Contents><Key>backup.sql</Key></Contents></ListBucketResult>'),
    ]
    strategy = CloudBucketExposureVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-bucket-1",
        target_url="http://target.test",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test", "bucket_url": "https://mybucket.s3.amazonaws.com"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.VERIFIED
    assert "Publicly listable cloud storage bucket confirmed" in conclusion.reason_description


@pytest.mark.asyncio
async def test_c063_cloud_bucket_false_positive_when_access_denied(mock_request_engine, default_budget):
    """C063: S3 bucket endpoint returns 403 AccessDenied -> NOT_REPRODUCIBLE."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R0", 200, "<html><body><script src='https://mybucket.s3.amazonaws.com/bundle.js'></script></body></html>"),
        make_evidence("R1", 403, "<Error><Code>AccessDenied</Code></Error>"),
    ]
    strategy = CloudBucketExposureVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-bucket-2",
        target_url="http://target.test",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test", "bucket_url": "https://mybucket.s3.amazonaws.com"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_c066_cleartext_storage_verified_on_localstorage_jwt(mock_request_engine, default_budget):
    """C066: JS contains localStorage.setItem('jwt', token) -> VERIFIED."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 200, "function login() { localStorage.setItem('jwt', userToken); }"),
    ]
    strategy = CleartextStorageVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-storage-1",
        target_url="http://target.test/app.js",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/app.js"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.VERIFIED
    assert "Client JavaScript stores sensitive authentication tokens" in conclusion.reason_description


@pytest.mark.asyncio
async def test_c066_cleartext_storage_false_positive_when_cookie_used(mock_request_engine, default_budget):
    """C066: JS contains only regular UI preferences in localStorage -> NOT_REPRODUCIBLE."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 200, "function setTheme() { localStorage.setItem('theme', 'dark'); }"),
    ]
    strategy = CleartextStorageVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-storage-2",
        target_url="http://target.test/app.js",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/app.js"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


# ──────────────────────────────────────────────────────────────────────────────
# GROUP 4 TESTS (Business Logic: Workflow Step Skipping & Replay Attack)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_c074_workflow_skipping_verified_on_unauthorized_completion(mock_request_engine, default_budget):
    """C074: Direct call to /api/order/complete returns 200 with order_id -> VERIFIED."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 200, json.dumps({"status": "success", "order_id": "ORD-999123", "message": "Order completed"})),
    ]
    strategy = WorkflowStepSkippingVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-wf-1",
        target_url="http://target.test/api/order/complete",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/api/order/complete"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.VERIFIED
    assert "Workflow completion endpoint" in conclusion.reason_description


@pytest.mark.asyncio
async def test_c074_workflow_skipping_false_positive_when_state_enforced(mock_request_engine, default_budget):
    """C074: Direct call to final step rejected with 400 Missing Stage -> NOT_REPRODUCIBLE."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 400, "Error: Missing cart checkout stage"),
    ]
    strategy = WorkflowStepSkippingVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-wf-2",
        target_url="http://target.test/api/order/complete",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/api/order/complete"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_c076_replay_attack_verified_on_double_execution(mock_request_engine, default_budget):
    """C076: Single-use transaction succeeds twice with identical 200 -> VERIFIED."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 200, json.dumps({"status": "processed", "amount": 100})),
        make_evidence("R2", 200, json.dumps({"status": "processed", "amount": 100})),
    ]
    strategy = ReplayAttackVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-replay-1",
        target_url="http://target.test/api/transfer",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/api/transfer"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.VERIFIED
    assert "accepted replayed single-use transaction payload twice" in conclusion.reason_description


@pytest.mark.asyncio
async def test_c076_replay_attack_false_positive_when_replay_prevented(mock_request_engine, default_budget):
    """C076: Replayed request is rejected with 409 Conflict/Nonce Used -> NOT_REPRODUCIBLE."""
    mock_request_engine.execute.side_effect = [
        make_evidence("R1", 200, json.dumps({"status": "processed", "amount": 100})),
        make_evidence("R2", 409, json.dumps({"error": "Nonce already consumed"})),
    ]
    strategy = ReplayAttackVerificationStrategy()

    ctx = VerificationContext(
        finding_id="f-replay-2",
        target_url="http://target.test/api/transfer",
        request_engine=mock_request_engine,
        candidate_evidence={"affected_url": "http://target.test/api/transfer"},
        budget=default_budget,
    )

    conclusion = await strategy.verify(ctx)
    assert conclusion.status == VerificationStatus.FALSE_POSITIVE



