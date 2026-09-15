"""Unit tests for Phase 24 AuthenticationAgent & Dual-Identity Isolation."""

import ast
import inspect
import json
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.agents.auth_agent import (
    AccountId,
    AccountAuthContext,
    AccountCredentialReference,
    AuthAgent,
    AuthState,
    MockBrowserDriver,
    SessionHandle,
    SharedAuthContext,
    mask_username,
)
from backend.models.database import AuthContextRecord, Base
from backend.models.migrations import run_migrations


@pytest.fixture
def test_db():
    """Create fresh in-memory SQLite database."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    run_migrations(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


class TestAccountConfigurationAndIsolation:
    """Validate Account 1 and Account 2 credential configuration and strict isolation."""

    def test_account_1_and_2_configuration_accepted(self):
        agent = AuthAgent(scan_id="CAMP-AUTH-1", config={"target_url": "https://app.example.com"})
        ref1 = agent.configure_account(
            account_id=AccountId.ACCOUNT_1.value,
            username="admin@example.com",
            password="Password123!",
        )
        ref2 = agent.configure_account(
            account_id=AccountId.ACCOUNT_2.value,
            username="user2@example.com",
            password="Password456!",
        )
        assert ref1.account_id == 1
        assert ref1.username_hint == "a***n@example.com"
        assert ref1.has_password is True
        assert ref2.account_id == 2
        assert ref2.username_hint == "u***2@example.com"
        assert ref2.has_password is True

    @pytest.mark.asyncio
    async def test_missing_account_configuration_handled(self):
        agent = AuthAgent(scan_id="CAMP-AUTH-2", config={"target_url": "https://app.example.com", "authorization_confirmed": True})
        ctx1 = await agent.authenticate_account(AccountId.ACCOUNT_1.value)
        assert ctx1.auth_status == AuthState.NOT_CONFIGURED.value
        assert agent.shared_context.account_1_authenticated is False

    @pytest.mark.asyncio
    async def test_account_1_and_2_have_independent_session_handles(self):
        driver = MockBrowserDriver(login_success=True)
        agent = AuthAgent(
            scan_id="CAMP-AUTH-3",
            config={"target_url": "https://app.example.com", "authorization_confirmed": True},
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "pass1")
        agent.configure_account(2, "user2@example.com", "pass2")

        ctx1 = await agent.authenticate_account(1)
        ctx2 = await agent.authenticate_account(2)

        assert ctx1.auth_status == AuthState.AUTHENTICATED.value
        assert ctx2.auth_status == AuthState.AUTHENTICATED.value

        sess1 = agent.shared_context.get_session(1)
        sess2 = agent.shared_context.get_session(2)

        assert sess1 is not None
        assert sess2 is not None
        # Strict isolation: Session A != Session B
        assert sess1.opaque_handle != sess2.opaque_handle
        assert sess1.account_id == 1
        assert sess2.account_id == 2
        assert sess1.opaque_handle.startswith("SESS-ACC1-")
        assert sess2.opaque_handle.startswith("SESS-ACC2-")

    @pytest.mark.asyncio
    async def test_account_1_cannot_retrieve_account_2_session(self):
        driver = MockBrowserDriver(login_success=True)
        agent = AuthAgent(
            scan_id="CAMP-AUTH-4",
            config={"target_url": "https://app.example.com", "authorization_confirmed": True},
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "pass1")
        agent.configure_account(2, "user2@example.com", "pass2")

        await agent.authenticate_account(1)
        await agent.authenticate_account(2)

        # Account 1 context should not hold Account 2's session
        acc1_ctx = agent.shared_context.account_contexts[1]
        assert acc1_ctx.session_handle.account_id == 1
        assert acc1_ctx.session_handle != agent.shared_context.get_session(2)

    @pytest.mark.asyncio
    async def test_shared_context_contains_both_states_without_secrets(self):
        driver = MockBrowserDriver(login_success=True)
        agent = AuthAgent(
            scan_id="CAMP-AUTH-5",
            config={"target_url": "https://app.example.com", "authorization_confirmed": True},
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "TopSecret123!")
        agent.configure_account(2, "user2@example.com", "TopSecret456!")

        await agent.authenticate_account(1)
        await agent.authenticate_account(2)

        safe_dict = agent.shared_context.to_safe_dict()
        assert safe_dict["account_1_authenticated"] is True
        assert safe_dict["account_2_authenticated"] is True
        assert safe_dict["account_1_session_valid"] is True
        assert safe_dict["account_2_session_valid"] is True

        serialized = json.dumps(safe_dict)
        # Verify zero secrets in shared context serialization
        assert "TopSecret123!" not in serialized
        assert "TopSecret456!" not in serialized
        assert "tok_" not in serialized  # Raw cookie values excluded from safe dict


class TestHumanInTheLoopMFAAndOTPWorkflow:
    """Validate OTP_REQUIRED, WAITING_FOR_OPERATOR, human submission, and immediate discard."""

    @pytest.mark.asyncio
    async def test_otp_challenge_transitions_to_waiting_for_operator(self):
        # Driver simulates MFA challenge
        driver = MockBrowserDriver(login_success=True, mfa_required=True, mfa_type="EMAIL_OTP")
        agent = AuthAgent(
            scan_id="CAMP-OTP-1",
            config={"target_url": "https://app.example.com", "authorization_confirmed": True},
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "pass1")

        ctx = await agent.authenticate_account(1)
        assert ctx.auth_status == AuthState.OTP_REQUIRED.value
        assert ctx.mfa_required is True
        assert ctx.mfa_type == "EMAIL_OTP"

        # Operator input requested
        prompt = agent.request_operator_input(1, challenge_type="EMAIL_OTP")
        assert prompt["status"] == AuthState.WAITING_FOR_OPERATOR.value
        assert prompt["account_id"] == 1
        assert ctx.auth_status == AuthState.WAITING_FOR_OPERATOR.value

    @pytest.mark.asyncio
    async def test_human_otp_submission_succeeds_and_discards_otp(self):
        driver = MockBrowserDriver(login_success=True, mfa_required=True, mfa_type="OTP", otp_success=True)
        agent = AuthAgent(
            scan_id="CAMP-OTP-2",
            config={"target_url": "https://app.example.com", "authorization_confirmed": True},
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "pass1")
        await agent.authenticate_account(1)
        agent.request_operator_input(1, challenge_type="OTP")

        # Operator enters OTP
        otp_secret = "839201"
        success, ctx = await agent.submit_operator_otp(1, otp_secret)
        assert success is True
        assert ctx.auth_status == AuthState.AUTHENTICATED.value
        assert ctx.session_handle is not None

        # Verify OTP was never stored in agent state or shared context
        safe_json = json.dumps(agent.shared_context.to_safe_dict())
        assert "839201" not in safe_json
        assert "839201" not in json.dumps(agent.shared_context.auth_events)

    @pytest.mark.asyncio
    async def test_invalid_otp_submission_fails(self):
        driver = MockBrowserDriver(login_success=True, mfa_required=True, mfa_type="OTP", otp_success=False)
        agent = AuthAgent(
            scan_id="CAMP-OTP-3",
            config={"target_url": "https://app.example.com", "authorization_confirmed": True},
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "pass1")
        await agent.authenticate_account(1)

        success, ctx = await agent.submit_operator_otp(1, "000000")
        assert success is False
        assert ctx.auth_status == AuthState.AUTH_FAILED.value
        assert ctx.session_handle is None


class TestSessionExpirationAndReAuthentication:
    """Validate expiration and isolated re-authentication."""

    @pytest.mark.asyncio
    async def test_session_expiration_affects_only_target_account(self):
        driver = MockBrowserDriver(login_success=True)
        agent = AuthAgent(
            scan_id="CAMP-EXP-1",
            config={"target_url": "https://app.example.com", "authorization_confirmed": True},
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "pass1")
        agent.configure_account(2, "user2@example.com", "pass2")

        await agent.authenticate_account(1)
        await agent.authenticate_account(2)

        # Expire Account 1 only
        agent.expire_session(1)

        assert agent.shared_context.account_1_authenticated is False
        assert agent.shared_context.account_1_session_valid is False
        assert agent.shared_context.account_contexts[1].auth_status == AuthState.SESSION_EXPIRED.value

        # Account 2 remains authenticated and valid!
        assert agent.shared_context.account_2_authenticated is True
        assert agent.shared_context.account_2_session_valid is True
        assert agent.shared_context.account_contexts[2].auth_status == AuthState.AUTHENTICATED.value

    @pytest.mark.asyncio
    async def test_reauthenticate_preserves_account_identity(self):
        driver = MockBrowserDriver(login_success=True)
        agent = AuthAgent(
            scan_id="CAMP-REAUTH-1",
            config={"target_url": "https://app.example.com", "authorization_confirmed": True},
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "pass1")
        agent.configure_account(2, "user2@example.com", "pass2")

        await agent.authenticate_account(1)
        agent.expire_session(1)

        ctx1 = await agent.reauthenticate(1)
        assert ctx1.auth_status == AuthState.AUTHENTICATED.value
        assert ctx1.session_handle.account_id == 1
        assert agent.shared_context.account_1_authenticated is True
        # Verify driver called login with Account 1 credentials, not Account 2
        assert driver.login_attempts[-1]["account_id"] == 1


class TestCrossAccountAuthorizationTestingFoundation:
    """Validate cross-account resource tracking and session validation for IDOR/BOLA."""

    @pytest.mark.asyncio
    async def test_cross_account_resource_context_and_validation(self):
        driver = MockBrowserDriver(login_success=True)
        agent = AuthAgent(
            scan_id="CAMP-IDOR-FOUNDATION-1",
            config={"target_url": "https://app.example.com", "authorization_confirmed": True},
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "pass1")
        agent.configure_account(2, "user2@example.com", "pass2")

        await agent.authenticate_account(1)
        await agent.authenticate_account(2)

        # Account 1 discovers resource 12345
        res_obs = agent.shared_context.register_resource(
            resource_id="order-12345",
            owner_account=1,
            path="/api/orders/12345",
            metadata={"amount": 99.99},
        )
        assert res_obs.owner_account == 1
        assert res_obs.resource_id in agent.shared_context.discovered_resources

        # Session validation for cross-account testing:
        sess1 = agent.shared_context.get_session(1)
        sess2 = agent.shared_context.get_session(2)

        # Actor 2 with Session 2 is VALID
        assert agent.shared_context.validate_actor_session(actor_account=2, session_handle=sess2) is True

        # Actor 2 with Session 1 is REJECTED (mismatched actor/session)
        assert agent.shared_context.validate_actor_session(actor_account=2, session_handle=sess1) is False

    @pytest.mark.asyncio
    async def test_request_engine_context_constructed_correctly(self):
        driver = MockBrowserDriver(login_success=True)
        agent = AuthAgent(
            scan_id="CAMP-REQ-CTX-1",
            config={"target_url": "https://app.example.com", "authorization_confirmed": True},
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "pass1")
        await agent.authenticate_account(1)

        req_ctx = agent.shared_context.build_request_context(1)
        assert req_ctx.name == "account_1"
        assert req_ctx.auth_type == "session_cookie"
        assert len(req_ctx.cookies) > 0


class TestPreconditionGatingAndSafety:
    """Validate concrete target, wildcard rejection, scope, and destination safety."""

    @pytest.mark.asyncio
    async def test_wildcard_target_rejected(self):
        driver = MockBrowserDriver()
        agent = AuthAgent(
            scan_id="CAMP-GATE-1",
            config={"target_url": "https://*.example.com", "authorization_confirmed": True},
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "pass1")
        ctx = await agent.authenticate_account(1)
        assert ctx.auth_status == AuthState.BLOCKED_SAFETY.value
        assert len(driver.login_attempts) == 0

    @pytest.mark.asyncio
    async def test_unauthorized_target_rejected(self):
        driver = MockBrowserDriver()
        agent = AuthAgent(
            scan_id="CAMP-GATE-2",
            config={"target_url": "https://app.example.com", "authorization_confirmed": False},
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "pass1")
        ctx = await agent.authenticate_account(1)
        assert ctx.auth_status == AuthState.BLOCKED_AUTHORIZATION.value
        assert len(driver.login_attempts) == 0

    @pytest.mark.asyncio
    async def test_out_of_scope_target_rejected(self):
        driver = MockBrowserDriver()
        agent = AuthAgent(
            scan_id="CAMP-GATE-3",
            config={
                "target_url": "https://unauthorized.target.com",
                "authorization_confirmed": True,
                "in_scope_assets": ["https://app.example.com"],
            },
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "pass1")
        ctx = await agent.authenticate_account(1)
        assert ctx.auth_status == AuthState.BLOCKED_SCOPE.value
        assert len(driver.login_attempts) == 0

    @pytest.mark.asyncio
    async def test_private_ip_destination_safety_rejected(self):
        driver = MockBrowserDriver()
        agent = AuthAgent(
            scan_id="CAMP-GATE-4",
            config={
                "target_url": "https://10.0.0.1",
                "authorization_confirmed": True,
                "in_scope_assets": ["https://10.0.0.1"],
            },
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "pass1")
        ctx = await agent.authenticate_account(1)
        assert ctx.auth_status == AuthState.BLOCKED_SAFETY.value
        assert len(driver.login_attempts) == 0


class TestDatabasePersistenceIntegration:
    """Validate AuthContextRecord persistence without plaintext secrets."""

    @pytest.mark.asyncio
    async def test_auth_context_persisted_to_db(self, test_db):
        driver = MockBrowserDriver(login_success=True)
        agent = AuthAgent(
            scan_id="CAMP-DB-AUTH-1",
            config={"target_url": "https://app.example.com", "authorization_confirmed": True},
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "SecretPass123!")
        await agent.authenticate_account(1, db=test_db)

        # Query database record
        rec = test_db.query(AuthContextRecord).filter_by(
            campaign_id="CAMP-DB-AUTH-1", account_id=1
        ).first()
        assert rec is not None
        assert rec.auth_status == AuthState.AUTHENTICATED.value
        assert rec.session_handle.startswith("SESS-ACC1-")
        assert rec.username_hint == "a***n@example.com"
        assert "SecretPass123!" not in rec.metadata_json


class TestDetailedAuthenticationScenarios:
    """Detailed tests for the 42 specific requirements."""

    def test_missing_account_2_configuration(self):
        agent = AuthAgent(scan_id="CAMP-DET-1", config={"target_url": "https://app.example.com"})
        agent.configure_account(1, "admin@example.com", "pass1")
        assert 1 in agent.credential_refs
        assert 2 not in agent.credential_refs
        assert agent.shared_context.get_session(2) is None

    @pytest.mark.asyncio
    async def test_account_1_and_2_distinct_cookies_never_copied(self):
        driver = MockBrowserDriver(login_success=True)
        agent = AuthAgent(
            scan_id="CAMP-DET-2",
            config={"target_url": "https://app.example.com", "authorization_confirmed": True},
            browser_driver=driver,
        )
        agent.configure_account(1, "user1@example.com", "p1")
        agent.configure_account(2, "user2@example.com", "p2")

        ctx1 = await agent.authenticate_account(1)
        ctx2 = await agent.authenticate_account(2)

        # Cookies in Account 1 must NOT be present in Account 2
        acc1_cookie_names = [c["name"] for c in ctx1._cookies]
        acc2_cookie_names = [c["name"] for c in ctx2._cookies]
        assert "session_acc1" in acc1_cookie_names
        assert "session_acc1" not in acc2_cookie_names
        assert "session_acc2" in acc2_cookie_names
        assert "session_acc2" not in acc1_cookie_names

    @pytest.mark.asyncio
    async def test_auth_failure_does_not_establish_session(self):
        driver = MockBrowserDriver(login_success=False)
        agent = AuthAgent(
            scan_id="CAMP-DET-3",
            config={"target_url": "https://app.example.com", "authorization_confirmed": True},
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "wrongpass")
        ctx = await agent.authenticate_account(1)
        assert ctx.auth_status == AuthState.AUTH_FAILED.value
        assert ctx.session_handle is None
        assert agent.shared_context.account_1_authenticated is False
        assert agent.shared_context.account_1_session_valid is False

    @pytest.mark.asyncio
    async def test_account_2_expiry_does_not_trigger_account_1_credentials(self):
        driver = MockBrowserDriver(login_success=True)
        agent = AuthAgent(
            scan_id="CAMP-DET-4",
            config={"target_url": "https://app.example.com", "authorization_confirmed": True},
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "pass1")
        agent.configure_account(2, "user2@example.com", "pass2")

        await agent.authenticate_account(1)
        await agent.authenticate_account(2)

        # Expire Account 2 only
        agent.expire_session(2)
        assert agent.shared_context.account_2_authenticated is False
        assert agent.shared_context.account_1_authenticated is True

        # Reauthenticate Account 2
        await agent.reauthenticate(2)
        assert driver.login_attempts[-1]["account_id"] == 2
        assert agent.shared_context.account_2_authenticated is True

    @pytest.mark.asyncio
    async def test_account_2_request_uses_session_b_for_account_1_resource(self):
        driver = MockBrowserDriver(login_success=True)
        agent = AuthAgent(
            scan_id="CAMP-DET-5",
            config={"target_url": "https://app.example.com", "authorization_confirmed": True},
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "pass1")
        agent.configure_account(2, "user2@example.com", "pass2")

        await agent.authenticate_account(1)
        await agent.authenticate_account(2)

        # Account 1 discovers resource
        res = agent.shared_context.register_resource("doc-999", owner_account=1, path="/docs/999")
        assert res.owner_account == 1

        # Build request context for Account 2
        req_ctx_2 = agent.shared_context.build_request_context(2)
        assert req_ctx_2.name == "account_2"
        assert "session_acc2" in req_ctx_2.cookies
        assert "session_acc1" not in req_ctx_2.cookies

    @pytest.mark.asyncio
    async def test_repeated_mocked_authentication_is_deterministic(self):
        driver = MockBrowserDriver(login_success=True)
        agent = AuthAgent(
            scan_id="CAMP-DET-6",
            config={"target_url": "https://app.example.com", "authorization_confirmed": True},
            browser_driver=driver,
        )
        agent.configure_account(1, "admin@example.com", "pass1")

        ctx_a = await agent.authenticate_account(1)
        status_a = ctx_a.auth_status
        agent.expire_session(1)
        ctx_b = await agent.authenticate_account(1)
        status_b = ctx_b.auth_status

        assert status_a == AuthState.AUTHENTICATED.value
        assert status_b == AuthState.AUTHENTICATED.value

    @pytest.mark.asyncio
    async def test_legacy_execute_compatibility(self):
        driver = MockBrowserDriver(login_success=True)
        agent = AuthAgent(
            scan_id="CAMP-DET-7",
            config={
                "target_url": "https://app.example.com",
                "authorization_confirmed": True,
                "primary_creds": {"username": "admin@example.com", "password": "pass1"},
                "secondary_creds": {"username": "user2@example.com", "password": "pass2"},
            },
            browser_driver=driver,
        )
        result = await agent.execute()
        assert isinstance(result, dict)
        assert result["authenticated"] is True
        assert result["primary"] is not None
        assert result["secondary"] is not None
        assert "shared_context" in result


class TestStaticSecurityChecks:
    """Ensure no forbidden constructs (subprocess, os.system, shell=True, eval, exec) exist in implementation."""

    def test_no_forbidden_constructs_in_auth_agent(self):
        import backend.agents.auth_agent as module

        source = inspect.getsource(module)
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "shell":
                        if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            pytest.fail(f"Forbidden shell=True found at line {node.lineno}")

                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("system", "popen"):
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                            pytest.fail(f"Forbidden os.{node.func.attr}() found at line {node.lineno}")
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                        pytest.fail(f"Direct subprocess call '{node.func.attr}' found at line {node.lineno}")

                if isinstance(node.func, ast.Name):
                    if node.func.id in ("eval", "exec"):
                        pytest.fail(f"Forbidden {node.func.id}() call found at line {node.lineno}")

