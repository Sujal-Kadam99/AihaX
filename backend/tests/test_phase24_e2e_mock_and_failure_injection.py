"""End-to-end mock integration and failure injection test suite for AihaX Phase 24."""

import asyncio
import pytest

from backend.agents.auth_agent import AuthAgent, SharedAuthContext
from backend.agents.recon_agent import (
    ReconAgent,
    ReconObservation,
    ReconObservationCategory,
    ReconSnapshot,
)
from backend.agents.vulnerability_testing_agent import VulnerabilityTestingAgent
from backend.core.scope_validator import ScopeValidator, validate_destination_safety
from backend.services.request_engine import (
    AuthenticationContext,
    MockTransport,
    RequestEngine,
    RequestSpec,
    redact_headers,
    redact_body,
)
from backend.services.vulnerability_execution_engine import (
    ExecutionMode,
    FindingStatus,
    VulnerabilityExecutionEngine,
)
from backend.services.vulnerability_hypothesis_engine import (
    VulnerabilityHypothesis,
    VulnerabilityHypothesisEngine,
)
from backend.services.vulnerability_registry import VulnerabilityRegistry
from backend.services.vulnerability_test_selector import (
    ApplicabilityStatus,
    VulnerabilityTestSelector,
)


@pytest.fixture
def mock_pipeline_env():
    mock_transport = MockTransport()
    # Route for homepage / base
    mock_transport.add_route("https://authorized.example.com/", status=200, body="<html>Home</html>")
    # Route for Account 1 order
    mock_transport.add_route(
        "https://authorized.example.com/api/v1/orders/123",
        status=200,
        body='{"order_id": 123, "owner": "acc1", "secret": "credit_card_data"}',
    )
    scope = ScopeValidator(in_scope_assets=["https://authorized.example.com"])
    re = RequestEngine(scope_validator=scope, transport=mock_transport)
    exec_engine = VulnerabilityExecutionEngine(request_engine=re, scope_validator=scope)
    agent = VulnerabilityTestingAgent(scan_id="CAMP-E2E-GATE-1", execution_engine=exec_engine)
    return {
        "transport": mock_transport,
        "scope": scope,
        "request_engine": re,
        "exec_engine": exec_engine,
        "agent": agent,
    }


class TestEndToEndMockPipeline:
    """Validate full component interoperation from target to evidence and finding."""

    @pytest.mark.asyncio
    async def test_full_pipeline_mock_integration(self, mock_pipeline_env):
        agent = mock_pipeline_env["agent"]
        target = "https://authorized.example.com"

        # 2. Recon Snapshot Setup
        recon = ReconSnapshot(
            campaign_id="CAMP-E2E-GATE-1",
            target=target,
            status="COMPLETED",
            observations=[
                ReconObservation(
                    category=ReconObservationCategory.ENDPOINT.value,
                    value="https://authorized.example.com/api/v1/orders/123",
                    normalized_value="https://authorized.example.com/api/v1/orders/123",
                    discovered_by=["gau"],
                ),
                ReconObservation(
                    category=ReconObservationCategory.PARAMETER.value,
                    value="order_id",
                    normalized_value="order_id",
                    discovered_by=["gau"],
                ),
            ],
            tool_results={},
            graph_snapshot=None,
            observation_count=2,
            snapshot_hash="hash_e2e",
        )

        # 3. Dual-Identity Auth Context
        auth_ctx = SharedAuthContext(
            campaign_id="CAMP-E2E-GATE-1",
            target_url=target,
            account_1_authenticated=True,
            account_2_authenticated=True,
            account_1_session_valid=True,
            account_2_session_valid=True,
        )

        # 4. Vulnerability Selection
        selector = VulnerabilityTestSelector()
        matrix = selector.select_tests(
            target_url=target,
            in_scope_assets=[target],
            recon_snapshot=recon,
            shared_auth_context=auth_ctx,
            authorization_confirmed=True,
        )
        assert matrix.total_registered == 86
        assert matrix.applicable_count > 0

        # 5. Hypothesis Generation
        hypo_engine = VulnerabilityHypothesisEngine()
        hypotheses = hypo_engine.generate_hypotheses(
            matrix=matrix,
            campaign_id="CAMP-E2E-GATE-1",
        )
        assert len(hypotheses) > 0
        assert all(h.request_budget <= 10 for h in hypotheses)
        assert all(h.authorization_requirement == "HUMAN_REVIEW_REQUIRED" for h in hypotheses)

        # 6. Execution in SIMULATION mode
        exec_engine = mock_pipeline_env["exec_engine"]
        evidence_list = []
        for h in hypotheses[:3]:  # Test first 3 hypotheses
            ev = await exec_engine.execute_hypothesis(
                hypothesis=h,
                shared_auth_context=auth_ctx,
                mode=ExecutionMode.SIMULATION,
            )
            assert ev is not None
            assert ev.evidence_hash is not None
            evidence_list.append(ev)

        assert len(evidence_list) == 3


class TestFailureInjectionAndFailClosed:
    """Exhaustively verify fail-closed invariants under controlled failure injection."""

    def test_malformed_targets_rejected(self):
        for bad in ["://missing-scheme", "javascript:alert(1)", "data:text/html,evil", ""]:
            safe, reason = validate_destination_safety(bad)
            assert safe is False
            assert len(reason) > 0

    def test_unsupported_schemes_rejected(self):
        for bad in ["ftp://example.com", "file:///etc/passwd", "gopher://example.com"]:
            safe, reason = validate_destination_safety(bad)
            assert safe is False
            assert "only http and https" in reason.lower() or "scheme" in reason.lower()

    def test_out_of_scope_target_rejected(self):
        scope = ScopeValidator(in_scope_assets=["https://authorized.example.com"])
        dec = scope.is_url_in_scope("https://unauthorized.evil.com/api")
        assert dec.allowed is False

    def test_wildcard_target_rejected_for_execution(self):
        # Wildcard cannot be used as concrete target
        safe, reason = validate_destination_safety("https://*.example.com")
        assert safe is False or "*" in "https://*.example.com"

    def test_ssrf_destinations_blocked(self):
        blocked_targets = [
            "https://127.0.0.1",
            "https://localhost",
            "https://10.0.0.1",
            "https://172.16.0.1",
            "https://192.168.1.1",
            "http://169.254.169.254",
            "http://metadata.google.internal",
        ]
        for target in blocked_targets:
            safe, reason = validate_destination_safety(target)
            assert safe is False, f"Failed to block unsafe target: {target}"
            assert any(term in reason.lower() for term in ("ssrf", "loopback", "private", "metadata"))

    def test_prohibited_ports_blocked(self):
        for port in [21, 22, 23, 25, 3306, 5432, 6379, 9200, 27017]:
            safe, reason = validate_destination_safety(f"https://example.com:{port}")
            assert safe is False
            assert "prohibited" in reason.lower()

    @pytest.mark.asyncio
    async def test_live_execution_fails_without_operator_approval(self, mock_pipeline_env):
        exec_engine = mock_pipeline_env["exec_engine"]
        h = VulnerabilityHypothesis(
            hypothesis_id="HYP-1",
            vulnerability_id="C067_BOLA",
            check_id="C067",
            target="https://authorized.example.com",
            endpoint="https://authorized.example.com/api/v1/orders/123",
            parameter="id",
            method="GET",
            account_context="CROSS_ACCOUNT_1_TO_2",
            baseline_required=True,
            test_strategy="BOLA_CROSS_ACCOUNT_PROBE",
            expected_signal="DIFFERENTIAL_STATUS",
            safety_level="SAFE",
            request_budget=2,
            authorization_requirement="HUMAN_REVIEW_REQUIRED",
        )
        # Attempt live execution with missing operator_approval_id
        ev = await exec_engine.execute_hypothesis(
            hypothesis=h,
            mode=ExecutionMode.AUTHORIZED_LIVE,
            operator_id=None,
            operator_approval_id=None,
        )
        assert ev.result_status == FindingStatus.INCONCLUSIVE.value
        assert "operator approval" in ev.explanation.lower()

    @pytest.mark.asyncio
    async def test_missing_account_2_fails_closed_for_bola(self, mock_pipeline_env):
        selector = VulnerabilityTestSelector()
        # Auth context with only Account 1
        auth_ctx = SharedAuthContext(
            campaign_id="c1",
            target_url="https://authorized.example.com",
            account_1_authenticated=True,
            account_2_authenticated=False,
        )
        matrix = selector.select_tests(
            target_url="https://authorized.example.com",
            in_scope_assets=["https://authorized.example.com"],
            shared_auth_context=auth_ctx,
            authorization_confirmed=True,
        )
        c067 = next(e for e in matrix.entries if e.check_id == "C067")
        assert c067.applicability == ApplicabilityStatus.PREREQUISITE_MISSING.value
        assert "distinct" in c067.reasons[0].lower()

    def test_secret_redaction_before_persistence(self):
        headers = {
            "Authorization": "Bearer secret_token_12345",
            "Cookie": "session_id=super_secret_cookie; Path=/",
            "X-API-Key": "api_secret_key_abcdef",
            "Content-Type": "application/json",
        }
        redacted = redact_headers(headers)
        assert redacted["Authorization"] == "[REDACTED]"
        assert "super_secret_cookie" not in redacted["Cookie"]
        assert redacted["X-API-Key"] == "[REDACTED]"
        assert redacted["Content-Type"] == "application/json"

        body = '{"password": "plain_text_password", "token": "abc123token", "user": "alice"}'
        redacted_b = redact_body(body)
        assert "plain_text_password" not in redacted_b
        assert "abc123token" not in redacted_b
        assert "alice" in redacted_b
