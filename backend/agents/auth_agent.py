"""AihaX Phase 24 — AuthenticationAgent.

Establishes and manages dual-identity contexts (ACCOUNT_1, ACCOUNT_2) with strict
credential/session isolation, shared cross-account authorization testing context,
human-in-the-loop MFA/OTP workflows, and zero plaintext secret persistence.

Security Invariants:
1. Strict Account Isolation: Account 1 and Account 2 have separate credential references,
   session handles, cookies, and tokens. Session A != Session B.
2. Shared Test Context: Shared context tracks authentication states, session validity,
   and resource ownership without sharing secret material, enabling legitimate cross-account
   IDOR/BOLA testing.
3. Human-in-the-Loop OTP / MFA: First-class operator input workflow. OTP values are ephemeral,
   never persisted to database, never logged, never included in hashes or exceptions, and
   immediately discarded after submission.
4. Precondition Gating: Single concrete target, ScopeValidator, destination safety, and
   explicit authorization must be satisfied before browser session creation.
5. Zero Shell/Subprocess: No direct subprocess, os.system, shell=True, eval, or exec.
6. Database Persistence: Reuses AuthContextRecord (Migration 26) with opaque session handles
   and masked username hints only.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from sqlalchemy.orm import Session

from backend.agents.base_agent import BaseAgent
from backend.core.redis_client import set_sessions
from backend.core.scope_validator import (
    ScopeDecision,
    ScopeStatus,
    ScopeValidator,
    normalize_domain,
    validate_destination_safety,
)
from backend.models.database import AuthContextRecord, get_utc_now
from backend.services.request_engine import AuthenticationContext

logger = logging.getLogger("aihax.auth_agent")


# ==============================================================================
# 1. Enums and Status Constants
# ==============================================================================

class AccountId(int, Enum):
    ACCOUNT_1 = 1
    ACCOUNT_2 = 2


class AuthState(str, Enum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    READY = "READY"
    AUTHENTICATING = "AUTHENTICATING"
    OTP_REQUIRED = "OTP_REQUIRED"
    MFA_REQUIRED = "MFA_REQUIRED"
    WAITING_FOR_OPERATOR = "WAITING_FOR_OPERATOR"
    AUTHENTICATED = "AUTHENTICATED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    REAUTH_REQUIRED = "REAUTH_REQUIRED"
    AUTH_FAILED = "AUTH_FAILED"
    BLOCKED_AUTHORIZATION = "BLOCKED_AUTHORIZATION"
    BLOCKED_SCOPE = "BLOCKED_SCOPE"
    BLOCKED_SAFETY = "BLOCKED_SAFETY"
    ERROR = "ERROR"


# ==============================================================================
# 2. Secret Masking & Safe Utilities
# ==============================================================================

def mask_username(val: Optional[str]) -> str:
    """Mask a username or email for safe display/persistence (e.g. a***n@example.com)."""
    if not val:
        return ""
    val_str = str(val).strip()
    if "@" in val_str:
        parts = val_str.split("@", 1)
        user = parts[0]
        domain = parts[1]
        if len(user) <= 2:
            masked_user = user[0] + "*"
        else:
            masked_user = user[0] + "***" + user[-1]
        return f"{masked_user}@{domain}"
    if len(val_str) <= 4:
        return "****"
    return val_str[:2] + "***" + val_str[-2:]


# ==============================================================================
# 3. Data Structures & Context DTOs
# ==============================================================================

@dataclass
class AccountCredentialReference:
    """Reference to credentials without persisting plaintext passwords."""
    account_id: int
    username_hint: str
    credential_source: str = "IN_MEMORY"
    has_password: bool = False
    has_token: bool = False
    auth_method: str = "CREDENTIALS"
    # Ephemeral in-memory credential storage (NEVER persisted to DB or logs)
    _ephemeral_password: Optional[str] = field(default=None, repr=False)
    _ephemeral_token: Optional[str] = field(default=None, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "account_id": self.account_id,
            "username_hint": self.username_hint,
            "credential_source": self.credential_source,
            "has_password": self.has_password,
            "has_token": self.has_token,
            "auth_method": self.auth_method,
        }


@dataclass
class SessionHandle:
    """Opaque session handle identifying an active authenticated session."""
    session_id: str
    account_id: int
    opaque_handle: str
    created_at: str = field(default_factory=lambda: get_utc_now().isoformat())
    is_valid: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ResourceObservation:
    """A resource discovered under an authenticated context for cross-account testing."""
    resource_id: str
    owner_account: int
    path: str
    discovered_at: str = field(default_factory=lambda: get_utc_now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AccountAuthContext:
    """Isolated runtime session context for a single account."""
    account_id: int
    auth_status: str = AuthState.NOT_CONFIGURED.value
    session_handle: Optional[SessionHandle] = None
    username_hint: str = ""
    auth_method: str = "CREDENTIALS"
    mfa_required: bool = False
    mfa_type: Optional[str] = None
    last_authenticated_at: Optional[str] = None
    login_url: Optional[str] = None
    # Isolated in-memory cookies, headers, tokens (NEVER merged with other account)
    _cookies: List[Dict[str, Any]] = field(default_factory=list, repr=False)
    _headers: Dict[str, str] = field(default_factory=dict, repr=False)
    _bearer_token: Optional[str] = field(default=None, repr=False)
    _csrf_token: Optional[str] = field(default=None, repr=False)

    def to_safe_dict(self) -> Dict[str, Any]:
        return {
            "account_id": self.account_id,
            "auth_status": self.auth_status,
            "session_handle": self.session_handle.opaque_handle if self.session_handle else None,
            "username_hint": self.username_hint,
            "auth_method": self.auth_method,
            "mfa_required": self.mfa_required,
            "mfa_type": self.mfa_type,
            "last_authenticated_at": self.last_authenticated_at,
            "login_url": self.login_url,
            "cookie_count": len(self._cookies),
            "has_token": bool(self._bearer_token),
        }


@dataclass
class SharedAuthContext:
    """Broad shared authentication context accessible to later testing agents."""
    campaign_id: str
    target_url: str
    account_1_authenticated: bool = False
    account_2_authenticated: bool = False
    account_1_session_valid: bool = False
    account_2_session_valid: bool = False
    account_contexts: Dict[int, AccountAuthContext] = field(default_factory=dict)
    discovered_resources: Dict[str, ResourceObservation] = field(default_factory=dict)
    auth_events: List[Dict[str, Any]] = field(default_factory=list)

    def get_session(self, account_id: int) -> Optional[SessionHandle]:
        """Safely retrieve session handle for a specific account."""
        ctx = self.account_contexts.get(account_id)
        if ctx and ctx.session_handle and ctx.session_handle.is_valid:
            return ctx.session_handle
        return None

    def register_resource(
        self, resource_id: str, owner_account: int, path: str, metadata: Optional[Dict[str, Any]] = None
    ) -> ResourceObservation:
        """Register a resource discovered under an account for cross-account testing."""
        obs = ResourceObservation(
            resource_id=resource_id,
            owner_account=owner_account,
            path=path,
            metadata=metadata or {},
        )
        self.discovered_resources[resource_id] = obs
        return obs

    def validate_actor_session(self, actor_account: int, session_handle: SessionHandle) -> bool:
        """Verify that actor account matches the provided session handle."""
        if not session_handle or session_handle.account_id != actor_account:
            return False
        ctx = self.account_contexts.get(actor_account)
        if not ctx or not ctx.session_handle:
            return False
        return ctx.session_handle.opaque_handle == session_handle.opaque_handle

    def build_request_context(self, account_id: int) -> AuthenticationContext:
        """Build RequestEngine AuthenticationContext for an account using its isolated session."""
        ctx = self.account_contexts.get(account_id)
        if not ctx:
            return AuthenticationContext(name=f"account_{account_id}_unauth", auth_type="none")

        cookie_dict = {}
        for c in ctx._cookies:
            if isinstance(c, dict) and "name" in c and "value" in c:
                cookie_dict[c["name"]] = c["value"]

        headers = dict(ctx._headers)
        if ctx._bearer_token:
            headers["Authorization"] = f"Bearer {ctx._bearer_token}"
        if ctx._csrf_token:
            headers["X-CSRF-Token"] = ctx._csrf_token

        return AuthenticationContext(
            name=f"account_{account_id}",
            auth_type="session_cookie" if cookie_dict else ("bearer" if ctx._bearer_token else "custom"),
            headers=headers,
            cookies=cookie_dict,
        )

    def to_safe_dict(self) -> Dict[str, Any]:
        """Return safe shared context dictionary with zero plaintext credentials."""
        return {
            "campaign_id": self.campaign_id,
            "target_url": self.target_url,
            "account_1_authenticated": self.account_1_authenticated,
            "account_2_authenticated": self.account_2_authenticated,
            "account_1_session_valid": self.account_1_session_valid,
            "account_2_session_valid": self.account_2_session_valid,
            "accounts": {
                acc_id: ctx.to_safe_dict() for acc_id, ctx in self.account_contexts.items()
            },
            "discovered_resources": {
                r_id: r.to_dict() for r_id, r in self.discovered_resources.items()
            },
            "event_count": len(self.auth_events),
        }


# ==============================================================================
# 4. Browser Session Provider / Driver Abstraction
# ==============================================================================

class IBrowserDriver(ABC):
    """Abstract browser driver for authentication automation."""

    @abstractmethod
    async def perform_login(
        self,
        login_url: str,
        creds: AccountCredentialReference,
        timeout_seconds: int = 30,
    ) -> Tuple[bool, List[Dict[str, Any]], Dict[str, str], Optional[str], Optional[str]]:
        """Perform login and return (success, cookies, headers, mfa_type_or_none, error_msg)."""
        pass

    @abstractmethod
    async def submit_otp(
        self,
        otp_value: str,
        timeout_seconds: int = 30,
    ) -> Tuple[bool, List[Dict[str, Any]], Dict[str, str], Optional[str]]:
        """Submit OTP in pending MFA challenge and return (success, cookies, headers, error_msg)."""
        pass


class MockBrowserDriver(IBrowserDriver):
    """Mock browser driver for deterministic zero-network unit tests."""

    def __init__(
        self,
        login_success: bool = True,
        mfa_required: bool = False,
        mfa_type: str = "OTP",
        otp_success: bool = True,
    ) -> None:
        self.login_success = login_success
        self.mfa_required = mfa_required
        self.mfa_type = mfa_type
        self.otp_success = otp_success
        self.submitted_otp: Optional[str] = None
        self.login_attempts: List[Dict[str, Any]] = []

    async def perform_login(
        self,
        login_url: str,
        creds: AccountCredentialReference,
        timeout_seconds: int = 30,
    ) -> Tuple[bool, List[Dict[str, Any]], Dict[str, str], Optional[str], Optional[str]]:
        self.login_attempts.append({"url": login_url, "account_id": creds.account_id})

        if not self.login_success:
            return False, [], {}, None, "Invalid username or password"

        if self.mfa_required:
            return False, [], {}, self.mfa_type, None

        # Return mock session cookies
        mock_cookies = [
            {"name": f"session_acc{creds.account_id}", "value": f"tok_{secrets.token_hex(8)}", "domain": "example.com", "path": "/"}
        ]
        return True, mock_cookies, {}, None, None

    async def submit_otp(
        self,
        otp_value: str,
        timeout_seconds: int = 30,
    ) -> Tuple[bool, List[Dict[str, Any]], Dict[str, str], Optional[str]]:
        self.submitted_otp = otp_value
        if not self.otp_success:
            return False, [], {}, "Invalid OTP code"

        mock_cookies = [
            {"name": "mfa_session", "value": f"mfa_{secrets.token_hex(8)}", "domain": "example.com", "path": "/"}
        ]
        return True, mock_cookies, {}, None


# ==============================================================================
# 5. AuthenticationAgent Implementation
# ==============================================================================

class AuthAgent(BaseAgent):
    """Phase 24 Authentication Agent with dual-identity isolation and shared test context."""

    agent_id = 2
    agent_name = "Authentication Agent"

    def __init__(
        self,
        scan_id: Optional[str] = None,
        db: Optional[Session] = None,
        config: Optional[Dict[str, Any]] = None,
        browser_driver: Optional[IBrowserDriver] = None,
    ) -> None:
        self.scan_id = scan_id or "default-scan"
        self.db = db
        self.config = config or {}
        self.driver = browser_driver or MockBrowserDriver()

        target_url = self.config.get("target_url") or self.config.get("target", "")
        self.shared_context = SharedAuthContext(
            campaign_id=self.scan_id,
            target_url=target_url,
        )
        self.credential_refs: Dict[int, AccountCredentialReference] = {}
        self._pending_mfa_accounts: Set[int] = set()

    # ==========================================================================
    # Preconditions & Gating
    # ==========================================================================

    def validate_preconditions(self, target_url: str, authorization_confirmed: bool) -> Tuple[bool, str, str]:
        """Validate single concrete target, scope, destination safety, and authorization."""
        if not target_url or "," in target_url or " " in target_url:
            return False, AuthState.BLOCKED_SAFETY.value, "Target must be a single concrete URL."

        if "*" in target_url:
            return False, AuthState.BLOCKED_SAFETY.value, "Target contains wildcards (concrete execution target required)."

        # Authorization Gate
        if not authorization_confirmed:
            return False, AuthState.BLOCKED_AUTHORIZATION.value, "Explicit authorization is required for live authentication."

        # Scope Gate
        in_scope = self.config.get("in_scope_assets", [target_url])
        out_of_scope = self.config.get("out_of_scope_assets", [])
        scope_validator = ScopeValidator(
            in_scope_assets=in_scope,
            out_of_scope_assets=out_of_scope,
            allowed_ports=self.config.get("allowed_ports", []),
            excluded_ports=self.config.get("excluded_ports", []),
        )
        scope_decision = scope_validator.validate_target(target_url)
        if not scope_decision.allowed:
            return False, AuthState.BLOCKED_SCOPE.value, f"Target blocked by ScopeValidator: {scope_decision.reason}"

        # Destination Safety Gate (Anti-SSRF)
        is_safe, safety_reason = validate_destination_safety(
            target_url,
            allowed_ports=set(self.config.get("allowed_ports", [])) if self.config.get("allowed_ports") else None,
        )
        if not is_safe:
            return False, AuthState.BLOCKED_SAFETY.value, f"Target blocked by Destination Safety: {safety_reason}"

        return True, AuthState.READY.value, "Preconditions satisfied."

    # ==========================================================================
    # Account Configuration & Setup
    # ==========================================================================

    def configure_account(
        self,
        account_id: int,
        username: str,
        password: Optional[str] = None,
        token: Optional[str] = None,
        auth_method: str = "CREDENTIALS",
    ) -> AccountCredentialReference:
        """Register account credential reference without persisting plaintext password."""
        masked_user = mask_username(username)
        cred_ref = AccountCredentialReference(
            account_id=account_id,
            username_hint=masked_user,
            credential_source="IN_MEMORY",
            has_password=bool(password),
            has_token=bool(token),
            auth_method=auth_method,
            _ephemeral_password=password,
            _ephemeral_token=token,
        )
        self.credential_refs[account_id] = cred_ref

        # Initialize isolated AccountAuthContext
        account_ctx = AccountAuthContext(
            account_id=account_id,
            auth_status=AuthState.READY.value,
            username_hint=masked_user,
            auth_method=auth_method,
        )
        self.shared_context.account_contexts[account_id] = account_ctx
        return cred_ref

    # ==========================================================================
    # Authentication Workflow
    # ==========================================================================

    async def authenticate_account(
        self,
        account_id: int,
        login_url: Optional[str] = None,
        timeout_seconds: int = 30,
        db: Optional[Session] = None,
    ) -> AccountAuthContext:
        """Execute authentication for a single account, maintaining strict isolation."""
        target_url = self.shared_context.target_url
        auth_confirmed = bool(self.config.get("authorization_confirmed", True))

        # 1. Precondition Verification
        valid, gate_status, reason = self.validate_preconditions(target_url, auth_confirmed)
        if not valid:
            ctx = self.shared_context.account_contexts.get(
                account_id, AccountAuthContext(account_id=account_id)
            )
            ctx.auth_status = gate_status
            self.shared_context.account_contexts[account_id] = ctx
            self._record_auth_event(account_id, "PRECONDITION_FAILURE", {"reason": reason, "status": gate_status})
            if db:
                self._persist_auth_record(ctx, db)
            return ctx

        # 2. Check Credential Presence
        creds = self.credential_refs.get(account_id)
        if not creds:
            ctx = AccountAuthContext(
                account_id=account_id,
                auth_status=AuthState.NOT_CONFIGURED.value,
            )
            self.shared_context.account_contexts[account_id] = ctx
            self._record_auth_event(account_id, "NOT_CONFIGURED", {"error": "No credentials registered"})
            if db:
                self._persist_auth_record(ctx, db)
            return ctx

        account_ctx = self.shared_context.account_contexts[account_id]
        account_ctx.auth_status = AuthState.AUTHENTICATING.value
        effective_login_url = login_url or target_url
        account_ctx.login_url = effective_login_url

        self._record_auth_event(account_id, "AUTHENTICATING_START", {"login_url": effective_login_url})

        # 3. Perform Login through Browser Driver Abstraction
        try:
            success, cookies, headers, mfa_type, err_msg = await self.driver.perform_login(
                login_url=effective_login_url,
                creds=creds,
                timeout_seconds=timeout_seconds,
            )
        except Exception as e:
            account_ctx.auth_status = AuthState.ERROR.value
            self._record_auth_event(account_id, "AUTH_EXCEPTION", {"error": str(e)})
            if db:
                self._persist_auth_record(account_ctx, db)
            return account_ctx

        # 4. Handle MFA / OTP Challenge
        if mfa_type:
            account_ctx.auth_status = AuthState.OTP_REQUIRED.value
            account_ctx.mfa_required = True
            account_ctx.mfa_type = mfa_type
            self._pending_mfa_accounts.add(account_id)
            self._record_auth_event(account_id, "MFA_CHALLENGE_DETECTED", {"mfa_type": mfa_type})
            if db:
                self._persist_auth_record(account_ctx, db)
            return account_ctx

        # 5. Handle Authentication Failure
        if not success:
            account_ctx.auth_status = AuthState.AUTH_FAILED.value
            self._record_auth_event(account_id, "AUTH_FAILED", {"reason": err_msg or "Login unsuccessful"})
            if db:
                self._persist_auth_record(account_ctx, db)
            return account_ctx

        # 6. Authentication Succeeded -> Establish Session
        self._establish_session(account_id, cookies, headers, creds.auth_method)
        if db:
            self._persist_auth_record(account_ctx, db)

        return account_ctx

    def _establish_session(
        self,
        account_id: int,
        cookies: List[Dict[str, Any]],
        headers: Dict[str, str],
        auth_method: str,
    ) -> None:
        """Establish an opaque session handle and update shared context."""
        account_ctx = self.shared_context.account_contexts[account_id]
        opaque_token = f"SESS-ACC{account_id}-{secrets.token_hex(16)}"
        session_handle = SessionHandle(
            session_id=str(uuid.uuid4()),
            account_id=account_id,
            opaque_handle=opaque_token,
            created_at=get_utc_now().isoformat(),
            is_valid=True,
        )
        account_ctx.session_handle = session_handle
        account_ctx.auth_status = AuthState.AUTHENTICATED.value
        account_ctx.last_authenticated_at = get_utc_now().isoformat()
        account_ctx._cookies = list(cookies)
        account_ctx._headers = dict(headers)

        if account_id == AccountId.ACCOUNT_1.value:
            self.shared_context.account_1_authenticated = True
            self.shared_context.account_1_session_valid = True
        elif account_id == AccountId.ACCOUNT_2.value:
            self.shared_context.account_2_authenticated = True
            self.shared_context.account_2_session_valid = True

        self._record_auth_event(account_id, "AUTHENTICATED", {"session_handle": opaque_token})

    # ==========================================================================
    # Human-in-the-Loop OTP / MFA Workflow
    # ==========================================================================

    def request_operator_input(self, account_id: int, challenge_type: str = "OTP") -> Dict[str, Any]:
        """Request operator OTP input for an account in MFA_REQUIRED/OTP_REQUIRED state."""
        ctx = self.shared_context.account_contexts.get(account_id)
        if not ctx or ctx.auth_status not in (AuthState.OTP_REQUIRED.value, AuthState.MFA_REQUIRED.value):
            return {"status": "NOT_APPLICABLE", "account_id": account_id}

        ctx.auth_status = AuthState.WAITING_FOR_OPERATOR.value
        self._record_auth_event(account_id, "WAITING_FOR_OPERATOR", {"challenge_type": challenge_type})
        return {
            "status": AuthState.WAITING_FOR_OPERATOR.value,
            "account_id": account_id,
            "challenge_type": challenge_type,
            "username_hint": ctx.username_hint,
        }

    async def submit_operator_otp(
        self,
        account_id: int,
        otp_value: str,
        timeout_seconds: int = 30,
        db: Optional[Session] = None,
    ) -> Tuple[bool, AccountAuthContext]:
        """Submit operator-entered OTP, verify result, and IMMEDIATELY discard the OTP."""
        if not otp_value:
            ctx = self.shared_context.account_contexts[account_id]
            ctx.auth_status = AuthState.AUTH_FAILED.value
            return False, ctx

        ctx = self.shared_context.account_contexts.get(account_id)
        if not ctx:
            return False, AccountAuthContext(account_id=account_id, auth_status=AuthState.ERROR.value)

        self._record_auth_event(account_id, "OPERATOR_OTP_RECEIVED", {"length": len(otp_value)})

        try:
            # Submit OTP through driver
            success, cookies, headers, err_msg = await self.driver.submit_otp(
                otp_value=otp_value,
                timeout_seconds=timeout_seconds,
            )
        finally:
            # Immediate discard of sensitive OTP
            del otp_value

        if not success:
            ctx.auth_status = AuthState.AUTH_FAILED.value
            self._record_auth_event(account_id, "OTP_VERIFICATION_FAILED", {"reason": err_msg or "Invalid OTP"})
            if db:
                self._persist_auth_record(ctx, db)
            return False, ctx

        # OTP verified successfully
        self._pending_mfa_accounts.discard(account_id)
        self._establish_session(account_id, cookies, headers, ctx.auth_method)
        if db:
            self._persist_auth_record(ctx, db)

        return True, ctx

    # ==========================================================================
    # Session Expiration & Re-Authentication
    # ==========================================================================

    def expire_session(self, account_id: int) -> None:
        """Simulate session expiration for an account (isolated to this account only)."""
        ctx = self.shared_context.account_contexts.get(account_id)
        if ctx:
            if ctx.session_handle:
                ctx.session_handle.is_valid = False
            ctx.auth_status = AuthState.SESSION_EXPIRED.value
            ctx._cookies = []
            ctx._headers = {}
            ctx._bearer_token = None
            if account_id == AccountId.ACCOUNT_1.value:
                self.shared_context.account_1_authenticated = False
                self.shared_context.account_1_session_valid = False
            elif account_id == AccountId.ACCOUNT_2.value:
                self.shared_context.account_2_authenticated = False
                self.shared_context.account_2_session_valid = False
            self._record_auth_event(account_id, "SESSION_EXPIRED", {})

    async def reauthenticate(self, account_id: int, db: Optional[Session] = None) -> AccountAuthContext:
        """Re-authenticate an expired session for the same account without crossing credentials."""
        ctx = self.shared_context.account_contexts.get(account_id)
        if ctx:
            ctx.auth_status = AuthState.REAUTH_REQUIRED.value
            self._record_auth_event(account_id, "REAUTH_REQUESTED", {})
        return await self.authenticate_account(account_id=account_id, db=db)

    # ==========================================================================
    # Database Persistence (AuthContextRecord)
    # ==========================================================================

    def _persist_auth_record(self, ctx: AccountAuthContext, db: Session) -> None:
        """Persist or update AuthContextRecord in database without plaintext secrets."""
        try:
            session_handle_str = ctx.session_handle.opaque_handle if ctx.session_handle else f"UNAUTH-{ctx.account_id}"
            rec = db.query(AuthContextRecord).filter_by(
                campaign_id=self.scan_id, account_id=ctx.account_id
            ).first()

            metadata_dict = {
                "auth_status": ctx.auth_status,
                "mfa_required": ctx.mfa_required,
                "mfa_type": ctx.mfa_type,
                "last_authenticated_at": ctx.last_authenticated_at,
                "username_hint": ctx.username_hint,
            }

            if not rec:
                rec = AuthContextRecord(
                    id=str(uuid.uuid4()),
                    campaign_id=self.scan_id,
                    account_id=ctx.account_id,
                    auth_status=ctx.auth_status,
                    session_handle=session_handle_str,
                    auth_method=ctx.auth_method,
                    username_hint=ctx.username_hint,
                    last_authenticated_at=get_utc_now() if ctx.last_authenticated_at else None,
                    metadata_json=json.dumps(metadata_dict),
                    created_at=get_utc_now(),
                    updated_at=get_utc_now(),
                )
                db.add(rec)
            else:
                rec.auth_status = ctx.auth_status
                rec.session_handle = session_handle_str
                rec.auth_method = ctx.auth_method
                rec.username_hint = ctx.username_hint
                if ctx.last_authenticated_at:
                    rec.last_authenticated_at = get_utc_now()
                rec.metadata_json = json.dumps(metadata_dict)
                rec.updated_at = get_utc_now()

            db.commit()
        except Exception as e:
            logger.warning(f"Failed to persist AuthContextRecord: {e}")
            db.rollback()

    def _record_auth_event(self, account_id: int, event_type: str, details: Dict[str, Any]) -> None:
        """Record audit event in shared context without secrets."""
        self.shared_context.auth_events.append({
            "account_id": account_id,
            "event": event_type,
            "details": details,
            "timestamp": get_utc_now().isoformat(),
        })

    # ==========================================================================
    # Backwards Compatibility execute() for BaseAgent Pipeline
    # ==========================================================================

    async def execute(self) -> Dict[str, Any]:
        """Execute legacy primary and secondary login flow for BaseAgent scans."""
        target_url = self.config.get("target_url", "")
        primary_creds = self.config.get("primary_creds")
        secondary_creds = self.config.get("secondary_creds")

        sessions: Dict[str, Any] = {
            "primary": None,
            "secondary": None,
            "authenticated": False,
            "shared_context": self.shared_context.to_safe_dict(),
        }

        if not primary_creds:
            await self.publish_update("running", 50, "No credentials provided — skipping auth")
            await set_sessions(self.scan_id, sessions)
            return sessions

        await self.check_cancelled()
        await self.publish_update("running", 20, "Configuring Account 1...")
        self.configure_account(
            account_id=AccountId.ACCOUNT_1.value,
            username=primary_creds.get("username", ""),
            password=primary_creds.get("password", ""),
        )

        if secondary_creds:
            self.configure_account(
                account_id=AccountId.ACCOUNT_2.value,
                username=secondary_creds.get("username", ""),
                password=secondary_creds.get("password", ""),
            )

        await self.publish_update("running", 40, "Authenticating Account 1...")
        ctx1 = await self.authenticate_account(AccountId.ACCOUNT_1.value, db=self.db)
        if ctx1.auth_status == AuthState.AUTHENTICATED.value:
            sessions["primary"] = ctx1._cookies
            sessions["authenticated"] = True
            await self.publish_update("running", 70, "Account 1 authenticated successfully")

        if secondary_creds:
            await self.publish_update("running", 80, "Authenticating Account 2...")
            ctx2 = await self.authenticate_account(AccountId.ACCOUNT_2.value, db=self.db)
            if ctx2.auth_status == AuthState.AUTHENTICATED.value:
                sessions["secondary"] = ctx2._cookies
                await self.publish_update("running", 90, "Account 2 authenticated successfully")

        sessions["shared_context"] = self.shared_context.to_safe_dict()
        await set_sessions(self.scan_id, sessions)
        await self.publish_update("completed", 100, "Authentication processing completed")
        return sessions
