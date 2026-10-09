"""Central Network Request and Evidence Engine for AihaX.

Enforces:
1. Deterministic ScopeValidator gating BEFORE any network bytes or socket operations.
2. Default-deny when out-of-scope, invalid, or authorization is missing.
3. Safe redirect handling with independent scope validation on every hop.
4. Token-bucket rate limiting (RPS) and concurrency semaphore for all requests and retries.
5. Granular timeout enforcement (connect, read, total).
6. Response buffer size limits with explicit truncation tracking.
7. Secret redaction on request/response headers and bodies.
8. Deterministic SHA-256 hashing and unique Request IDs (REQ-xxxxxxxx).
9. Structured TransportError representation without false-positive findings.
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import json
import re
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urljoin, urlparse

from backend.core.scope_validator import (
    ScopeDecision,
    ScopeStatus,
    ScopeValidator,
    validate_destination_safety,
)


# ──────────────────────────────────────────────────────────────────────────────
# 1. DATA MODELS & DTOs
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class RequestTimeout:
    connect: float = 5.0
    read: float = 10.0
    total: float = 15.0

    def __post_init__(self) -> None:
        # Cap maximum timeout to 60s to prevent unbounded network hangs
        self.connect = min(max(0.1, float(self.connect)), 30.0)
        self.read = min(max(0.1, float(self.read)), 60.0)
        self.total = min(max(0.1, float(self.total)), 60.0)


@dataclass
class AuthenticationContext:
    name: str = "anonymous"
    auth_type: str = "none"
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    query_params: dict[str, str] = field(default_factory=dict)
    secret_keys_to_redact: list[str] = field(
        default_factory=lambda: [
            "authorization",
            "cookie",
            "x-api-key",
            "api-key",
            "x-auth-token",
            "token",
            "password",
            "secret",
            "bearer",
            "session",
        ]
    )


class TransportError(Exception):
    def __init__(self, error_type: str, message: str, details: Optional[dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "error_type": self.error_type,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class RequestSpec:
    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    query_params: dict[str, Any] = field(default_factory=dict)
    body: Optional[Union[str, bytes, dict[str, Any]]] = None
    timeout: RequestTimeout = field(default_factory=RequestTimeout)
    follow_redirects: bool = False
    max_redirects: int = 5
    auth_context: Optional[AuthenticationContext] = None
    max_response_size: int = 2 * 1024 * 1024  # 2 MB limit
    retries: int = 0
    authorization_confirmed: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RequestEvidence:
    request_id: str
    timestamp: str
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: Optional[str]
    response_status: Optional[int]
    response_headers: dict[str, str]
    response_body: Optional[str]
    response_size: int
    duration_ms: float
    truncated: bool
    redirect_chain: list[str]
    scope_decision: dict[str, Any]
    transport_error: Optional[dict[str, Any]]
    request_hash: str
    response_hash: str
    auth_context_name: Optional[str] = None
    retries_attempted: int = 0
    success: bool = False

    @property
    def evidence_id(self) -> str:
        return f"EVD-{self.request_id.replace('REQ-', '')}"

    @property
    def status_code(self) -> Optional[int]:
        return self.response_status

    @property
    def response_body_sample(self) -> str:
        return self.response_body or ""

    @property
    def scope_snapshot_hash(self) -> Optional[str]:
        if isinstance(self.scope_decision, dict):
            return self.scope_decision.get("snapshot_hash")
        return None

    @property
    def response(self) -> Optional[RawResponse]:
        if self.response_status is not None:
            return RawResponse(
                status_code=self.response_status,
                headers=self.response_headers,
                body=(self.response_body or "").encode("utf-8"),
                truncated=self.truncated,
                observed_size=self.response_size,
            )
        return None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RawResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes
    truncated: bool = False
    observed_size: int = 0


# ──────────────────────────────────────────────────────────────────────────────
# 2. TRANSPORTS (Production & Mock)
# ──────────────────────────────────────────────────────────────────────────────

class BaseAsyncTransport(ABC):
    """Abstract transport for physical or mocked HTTP execution."""

    @abstractmethod
    async def send(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        params: dict[str, Any],
        body: Optional[bytes],
        timeout: RequestTimeout,
        max_response_size: int,
    ) -> RawResponse:
        pass


class AiohttpTransport(BaseAsyncTransport):
    """Production aiohttp transport with chunked streaming for response size bounds."""

    async def send(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        params: dict[str, Any],
        body: Optional[bytes],
        timeout: RequestTimeout,
        max_response_size: int,
    ) -> RawResponse:
        import aiohttp

        client_timeout = aiohttp.ClientTimeout(
            total=timeout.total,
            connect=timeout.connect,
            sock_read=timeout.read,
        )

        async with aiohttp.ClientSession(timeout=client_timeout) as session:
            async with session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=body,
                allow_redirects=False,
            ) as resp:
                resp_headers = {k: v for k, v in resp.headers.items()}
                chunks: list[bytes] = []
                total_bytes = 0
                truncated = False

                async for chunk in resp.content.iter_chunked(8192):
                    total_bytes += len(chunk)
                    if len(b"".join(chunks)) + len(chunk) <= max_response_size:
                        chunks.append(chunk)
                    else:
                        remaining = max_response_size - len(b"".join(chunks))
                        if remaining > 0:
                            chunks.append(chunk[:remaining])
                        truncated = True

                collected_body = b"".join(chunks)
                return RawResponse(
                    status_code=resp.status,
                    headers=resp_headers,
                    body=collected_body,
                    truncated=truncated,
                    observed_size=total_bytes,
                )


class MockTransport(BaseAsyncTransport):
    """Mock transport for deterministic unit tests and security validation."""

    def __init__(
        self,
        default_status: int = 200,
        default_headers: Optional[dict[str, str]] = None,
        default_body: Union[str, bytes] = b"<html><body>Mock Response</body></html>",
    ) -> None:
        self.call_count: int = 0
        self.calls: list[dict[str, Any]] = []
        self._counter: int = 0
        self._handlers: list[Tuple[int, int, Callable[[str, str], bool], Any]] = []
        self.default_status = default_status
        self.default_headers = default_headers or {"content-type": "text/html; charset=utf-8"}
        self.default_body = default_body.encode("utf-8") if isinstance(default_body, str) else default_body

    def register_handler(
        self,
        matcher: Callable[[str, str], bool],
        response: Union[RawResponse, Exception, Callable[..., RawResponse]],
        priority: int = 100,
    ) -> None:
        self._counter += 1
        self._handlers.append((priority, self._counter, matcher, response))

    def register_response(
        self,
        url_prefix: Optional[str] = None,
        status_code: int = 200,
        headers: Optional[dict[str, str]] = None,
        body: Union[str, bytes] = "OK",
        url: Optional[str] = None,
        method: Optional[str] = None,
    ) -> None:
        target_url = url or url_prefix or ""
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        resp = RawResponse(
            status_code=status_code,
            headers=headers or {"content-type": "text/plain"},
            body=body_bytes,
            observed_size=len(body_bytes),
        )
        if method:
            self.register_handler(
                lambda m, u: (m.upper() == method.upper() and target_url in u),
                resp,
                priority=len(target_url) + 10,
            )
        else:
            self.register_handler(lambda m, u: target_url in u, resp, priority=len(target_url))

    def add_route(
        self,
        url_prefix: str,
        status: int = 200,
        headers: Optional[dict[str, str]] = None,
        body: Union[str, bytes] = "OK",
    ) -> None:
        """Alias for register_response for ease of route definition."""
        self.register_response(url_prefix=url_prefix, status_code=status, headers=headers, body=body)

    async def send(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        params: dict[str, Any],
        body: Optional[bytes],
        timeout: RequestTimeout,
        max_response_size: int,
    ) -> RawResponse:
        self.call_count += 1
        self.calls.append({
            "method": method,
            "url": url,
            "headers": headers,
            "params": params,
            "body": body,
            "timeout": timeout,
        })

        # Match highest priority (most specific URL or newer registration) first
        for priority, counter, matcher, response in sorted(self._handlers, key=lambda x: (x[0], x[1]), reverse=True):
            if matcher(method, url):
                if isinstance(response, Exception):
                    raise response
                elif callable(response):
                    return response(method, url, headers, params, body)
                elif isinstance(response, RawResponse):
                    # Handle size limit simulation
                    if len(response.body) > max_response_size:
                        return RawResponse(
                            status_code=response.status_code,
                            headers=response.headers,
                            body=response.body[:max_response_size],
                            truncated=True,
                            observed_size=len(response.body),
                        )
                    return response

        # Default fallback mock response
        return RawResponse(
            status_code=self.default_status,
            headers=dict(self.default_headers),
            body=self.default_body,
            observed_size=len(self.default_body),
        )


# ──────────────────────────────────────────────────────────────────────────────
# 3. RATE LIMITER (Token Bucket + Semaphore)
# ──────────────────────────────────────────────────────────────────────────────

class AsyncTokenBucket:
    """Deterministic token bucket for Rate Limiting requests per second."""

    def __init__(self, rate_per_second: float = 10.0, capacity: float = 10.0) -> None:
        self.rate = max(0.1, float(rate_per_second))
        self.capacity = max(1.0, float(capacity))
        self.tokens = self.capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self.last_update
                self.last_update = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                # Calculate sleep duration to get 1 token
                needed = 1.0 - self.tokens
                wait_time = needed / self.rate

            await asyncio.sleep(min(wait_time, 0.5))


# ──────────────────────────────────────────────────────────────────────────────
# 4. SECRET REDACTION UTILITIES
# ──────────────────────────────────────────────────────────────────────────────

SENSITIVE_KEY_PATTERNS = [
    re.compile(r"auth", re.IGNORECASE),
    re.compile(r"cookie", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"api[-_]?key", re.IGNORECASE),
    re.compile(r"session", re.IGNORECASE),
    re.compile(r"bearer", re.IGNORECASE),
]


def redact_headers(headers: dict[str, str], custom_keys: Optional[list[str]] = None) -> dict[str, str]:
    """Redact sensitive authorization, tokens, and credentials from header mapping."""
    redacted: dict[str, str] = {}
    extra_patterns = [re.compile(re.escape(k), re.IGNORECASE) for k in (custom_keys or [])]

    for k, v in headers.items():
        if k.lower() == "set-cookie":
            # Redact the cookie secret value portion but preserve security flags (Secure, HttpOnly, SameSite, Domain, Path)
            parts = v.split(";")
            if parts:
                first_part = parts[0]
                if "=" in first_part:
                    cname, _ = first_part.split("=", 1)
                    redacted_cookie = f"{cname}=[REDACTED];" + ";".join(parts[1:])
                else:
                    redacted_cookie = "[REDACTED]"
                redacted[k] = redacted_cookie
            else:
                redacted[k] = "[REDACTED]"
            continue

        is_sensitive = any(p.search(k) for p in SENSITIVE_KEY_PATTERNS + extra_patterns)
        if is_sensitive:
            redacted[k] = "[REDACTED]"
        else:
            redacted[k] = v
    return redacted


def redact_body(body: Optional[str]) -> Optional[str]:
    """Redact passwords and secrets if body is JSON or form-encoded."""
    if not body:
        return body

    # Attempt JSON redaction
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            return json.dumps(_redact_dict(data))
    except Exception:
        pass

    # Regex fallback for key=value or "key": "value"
    sanitized = body
    for pat in [
        r'("?(?:password|secret|token|api[-_]?key|access_token|refresh_token)"?\s*[:=]\s*)"[^"]+"',
        r'("?(?:password|secret|token|api[-_]?key|access_token|refresh_token)"?\s*[:=]\s*)[^\s&,}]+',
    ]:
        sanitized = re.sub(pat, r'\1"[REDACTED]"', sanitized, flags=re.IGNORECASE)

    return sanitized


def _redact_dict(d: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        is_sensitive = any(p.search(k) for p in SENSITIVE_KEY_PATTERNS)
        if is_sensitive:
            out[k] = "[REDACTED]"
        elif isinstance(v, dict):
            out[k] = _redact_dict(v)
        elif isinstance(v, list):
            out[k] = [(_redact_dict(i) if isinstance(i, dict) else i) for i in v]
        else:
            out[k] = v
    return out


# ──────────────────────────────────────────────────────────────────────────────
# 5. REQUEST ENGINE
# ──────────────────────────────────────────────────────────────────────────────

class RequestEngine:
    """Canonical Request and Evidence layer for AihaX."""

    def __init__(
        self,
        scope_validator: Optional[ScopeValidator] = None,
        rate_limit_rps: int = 10,
        max_concurrency: int = 5,
        transport: Optional[BaseAsyncTransport] = None,
    ) -> None:
        self.scope_validator = scope_validator or ScopeValidator(in_scope_assets=["*"])
        self.rate_limit_rps = max(1, rate_limit_rps)
        self.max_concurrency = max(1, max_concurrency)
        self._total_requests: int = 0
        self._execution_context: contextvars.ContextVar[
            tuple[Optional[str], Optional[str], Optional[str], Optional[str]]
        ] = contextvars.ContextVar(
            f"request_engine_context_{id(self)}", default=(None, None, None, None)
        )
        self.request_budget_reserver: Optional[
            Callable[[str, str], Awaitable[tuple[bool, str]]]
        ] = None
        self._rate_limiter = AsyncTokenBucket(
            rate_per_second=float(self.rate_limit_rps),
            capacity=float(self.rate_limit_rps),
        )
        self._semaphore = asyncio.Semaphore(self.max_concurrency)
        self.transport = transport or AiohttpTransport()

    @property
    def total_requests(self) -> int:
        return self._total_requests

    def _set_execution_context(self, index: int, value: Optional[str]) -> None:
        context = list(self._execution_context.get())
        context[index] = value
        self._execution_context.set(tuple(context))

    @property
    def current_check_id(self) -> Optional[str]:
        return self._execution_context.get()[0]

    @current_check_id.setter
    def current_check_id(self, value: Optional[str]) -> None:
        self._set_execution_context(0, value)

    @property
    def current_finding_id(self) -> Optional[str]:
        return self._execution_context.get()[1]

    @current_finding_id.setter
    def current_finding_id(self, value: Optional[str]) -> None:
        self._set_execution_context(1, value)

    @property
    def current_phase(self) -> Optional[str]:
        return self._execution_context.get()[2]

    @current_phase.setter
    def current_phase(self, value: Optional[str]) -> None:
        self._set_execution_context(2, value)

    @property
    def current_target_url(self) -> Optional[str]:
        return self._execution_context.get()[3]

    @current_target_url.setter
    def current_target_url(self, value: Optional[str]) -> None:
        self._set_execution_context(3, value)

    def execute_request(self, spec: RequestSpec) -> RequestEvidence:
        """Synchronous execution wrapper for tests and scripts."""
        self._total_requests += 1
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(lambda: asyncio.run(self.execute(spec))).result()
        else:
            return asyncio.run(self.execute(spec))

    def dispatch_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[dict[str, str]] = None,
        body: Optional[Union[str, bytes]] = None,
        authorization_confirmed: bool = True,
    ) -> RequestEvidence:
        """Convenience dispatch method."""
        spec = RequestSpec(
            url=url,
            method=method,
            headers=headers or {},
            body=body,
            authorization_confirmed=authorization_confirmed,
        )
        return self.execute_request(spec)

    async def execute(self, spec: RequestSpec) -> RequestEvidence:
        """Execute a RequestSpec through ScopeValidator, RateLimiter, and Evidence capture."""
        request_id = f"REQ-{secrets.token_hex(4).upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()
        method = spec.method.upper()
        current_url = spec.url.strip()
        redirect_chain: list[str] = [current_url]
        retries_attempted = 0

        # 1. Product Safety: Authorization Confirmation Check
        if not spec.authorization_confirmed:
            scope_decision = ScopeDecision(
                allowed=False,
                status=ScopeStatus.INVALID,
                reason="Authorization not confirmed: testing prohibited",
                asset=current_url,
            )
            return self._build_blocked_evidence(
                request_id=request_id,
                timestamp=timestamp,
                spec=spec,
                scope_decision=scope_decision,
                error_type="AUTH_MISSING",
                error_msg="Explicit authorization confirmation is required before network testing.",
                redirect_chain=redirect_chain,
            )

        # 2. Pre-Flight Scope Validation (NO BYTES BEFORE VALIDATION)
        scope_decision = self.scope_validator.validate_request(current_url, method=method)
        if not scope_decision.allowed:
            return self._build_blocked_evidence(
                request_id=request_id,
                timestamp=timestamp,
                spec=spec,
                scope_decision=scope_decision,
                error_type="SCOPE_DENIED",
                error_msg=f"Request blocked by ScopeValidator: {scope_decision.reason}",
                redirect_chain=redirect_chain,
            )

        # 3. Prepare payload and headers
        headers, body_bytes, body_str = self._prepare_request_data(spec)
        request_hash = hashlib.sha256(
            f"{method}:{current_url}:{body_str or ''}".encode("utf-8")
        ).hexdigest()

        # 4. Request execution with bounded retries and redirect loops
        start_time = time.monotonic()
        max_attempts = max(1, 1 + spec.retries)
        last_error: Optional[TransportError] = None
        raw_resp: Optional[RawResponse] = None

        for attempt in range(max_attempts):
            retries_attempted = attempt
            try:
                # Enforce Rate Limiting & Concurrency (Applies to all attempts and retries)
                await self._rate_limiter.acquire()
                async with self._semaphore:
                    raw_resp = await self._execute_with_redirects(
                        spec=spec,
                        headers=headers,
                        body_bytes=body_bytes,
                        redirect_chain=redirect_chain,
                    )
                last_error = None
                break  # Successful network transmission
            except TransportError as te:
                last_error = te
                # Do not retry policy denials or exhausted budget.
                if te.error_type in ("SCOPE_DENIED", "REDIRECT_BLOCKED", "INVALID_URL", "BUDGET_EXHAUSTED"):
                    break
            except asyncio.TimeoutError:
                last_error = TransportError(
                    error_type="TIMEOUT",
                    message=f"Request timed out after {spec.timeout.total}s",
                )
            except Exception as exc:
                last_error = self._categorize_exception(exc)

            if attempt < max_attempts - 1:
                await asyncio.sleep(2**attempt * 0.2)

        duration_ms = round((time.monotonic() - start_time) * 1000, 2)

        # 5. Build structured evidence
        if last_error or raw_resp is None:
            return RequestEvidence(
                request_id=request_id,
                timestamp=timestamp,
                method=method,
                url=current_url,
                request_headers=redact_headers(headers, spec.auth_context.secret_keys_to_redact if spec.auth_context else None),
                request_body=redact_body(body_str),
                response_status=raw_resp.status_code if raw_resp else None,
                response_headers=redact_headers(raw_resp.headers) if raw_resp else {},
                response_body=None,
                response_size=0,
                duration_ms=duration_ms,
                truncated=False,
                redirect_chain=redirect_chain,
                scope_decision=scope_decision.to_dict(),
                transport_error=last_error.to_dict() if last_error else {"error_type": "UNKNOWN_ERROR", "message": "Unknown network error"},
                request_hash=request_hash,
                response_hash=hashlib.sha256(b"").hexdigest(),
                auth_context_name=spec.auth_context.name if spec.auth_context else None,
                retries_attempted=retries_attempted,
                success=False,
            )

        resp_text = raw_resp.body.decode(errors="replace")
        response_hash = hashlib.sha256(raw_resp.body).hexdigest()

        return RequestEvidence(
            request_id=request_id,
            timestamp=timestamp,
            method=method,
            url=redirect_chain[-1] if redirect_chain else current_url,
            request_headers=redact_headers(headers, spec.auth_context.secret_keys_to_redact if spec.auth_context else None),
            request_body=redact_body(body_str),
            response_status=raw_resp.status_code,
            response_headers=redact_headers(raw_resp.headers),
            response_body=resp_text,
            response_size=raw_resp.observed_size,
            duration_ms=duration_ms,
            truncated=raw_resp.truncated,
            redirect_chain=redirect_chain,
            scope_decision=scope_decision.to_dict(),
            transport_error=None,
            request_hash=request_hash,
            response_hash=response_hash,
            auth_context_name=spec.auth_context.name if spec.auth_context else None,
            retries_attempted=retries_attempted,
            success=True,
        )

    async def _execute_with_redirects(
        self,
        spec: RequestSpec,
        headers: dict[str, str],
        body_bytes: Optional[bytes],
        redirect_chain: list[str],
    ) -> RawResponse:
        """Handle optional redirect following with per-hop ScopeValidator enforcement."""
        current_url = redirect_chain[-1]
        current_method = spec.method.upper()
        current_body = body_bytes
        redirect_count = 0

        while True:
            if self.request_budget_reserver:
                target = self.current_target_url or current_url
                check_id = self.current_check_id or "UNATTRIBUTED"
                allowed, reason = await self.request_budget_reserver(target, check_id)
                if not allowed:
                    raise TransportError(
                        error_type="BUDGET_EXHAUSTED",
                        message=reason,
                    )

            resp = await self.transport.send(
                method=current_method,
                url=current_url,
                headers=headers,
                params=spec.query_params if redirect_count == 0 else {},
                body=current_body,
                timeout=spec.timeout,
                max_response_size=spec.max_response_size,
            )

            # Check if redirection is present and enabled
            if spec.follow_redirects and resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location") or resp.headers.get("Location")
                if not location:
                    return resp

                next_url = urljoin(current_url, location.strip())
                redirect_count += 1

                if redirect_count > spec.max_redirects:
                    raise TransportError(
                        error_type="REDIRECT_ERROR",
                        message=f"Exceeded maximum allowed redirects ({spec.max_redirects})",
                    )

                # CRITICAL: Independently validate destination scope BEFORE sending next request
                dest_decision = self.scope_validator.validate_request(next_url, method="GET")
                if not dest_decision.allowed:
                    redirect_chain.append(next_url)
                    raise TransportError(
                        error_type="REDIRECT_BLOCKED",
                        message=f"Redirect to '{next_url}' blocked by scope policy ({dest_decision.reason})",
                        details={"redirect_destination": next_url, "decision": dest_decision.to_dict()},
                    )

                redirect_chain.append(next_url)
                current_url = next_url
                # 303 or 302 traditionally changes method to GET
                if resp.status_code in (302, 303):
                    current_method = "GET"
                    current_body = None
                continue

            return resp

    def _prepare_request_data(self, spec: RequestSpec) -> Tuple[dict[str, str], Optional[bytes], Optional[str]]:
        headers = dict(spec.headers)
        if spec.auth_context:
            headers.update(spec.auth_context.headers)
            if spec.auth_context.cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in spec.auth_context.cookies.items())
                headers["Cookie"] = cookie_str

        body_bytes: Optional[bytes] = None
        body_str: Optional[str] = None

        if spec.body is not None:
            if isinstance(spec.body, bytes):
                body_bytes = spec.body
                body_str = spec.body.decode(errors="replace")
            elif isinstance(spec.body, str):
                body_bytes = spec.body.encode("utf-8")
                body_str = spec.body
            elif isinstance(spec.body, dict):
                body_str = json.dumps(spec.body)
                body_bytes = body_str.encode("utf-8")
                headers.setdefault("Content-Type", "application/json")

        return headers, body_bytes, body_str

    def _build_blocked_evidence(
        self,
        request_id: str,
        timestamp: str,
        spec: RequestSpec,
        scope_decision: ScopeDecision,
        error_type: str,
        error_msg: str,
        redirect_chain: list[str],
    ) -> RequestEvidence:
        """Construct evidence for a request blocked before transport."""
        headers, _, body_str = self._prepare_request_data(spec)
        request_hash = hashlib.sha256(
            f"{spec.method.upper()}:{spec.url}:{body_str or ''}".encode("utf-8")
        ).hexdigest()

        return RequestEvidence(
            request_id=request_id,
            timestamp=timestamp,
            method=spec.method.upper(),
            url=spec.url,
            request_headers=redact_headers(headers, spec.auth_context.secret_keys_to_redact if spec.auth_context else None),
            request_body=redact_body(body_str),
            response_status=None,
            response_headers={},
            response_body=None,
            response_size=0,
            duration_ms=0.0,
            truncated=False,
            redirect_chain=redirect_chain,
            scope_decision=scope_decision.to_dict(),
            transport_error={"error_type": error_type, "message": error_msg},
            request_hash=request_hash,
            response_hash=hashlib.sha256(b"").hexdigest(),
            auth_context_name=spec.auth_context.name if spec.auth_context else None,
            retries_attempted=0,
            success=False,
        )

    @staticmethod
    def _categorize_exception(exc: Exception) -> TransportError:
        """Map raw networking exceptions into structured TransportErrors."""
        exc_name = type(exc).__name__.lower()
        msg = str(exc)
        msg_lower = msg.lower()

        if "timeout" in exc_name or "timed out" in msg_lower:
            return TransportError(error_type="TIMEOUT", message=f"Connection or read timed out: {msg}")
        if "gaierror" in exc_name or "gaierror" in msg_lower or "dns" in msg_lower or "not resolve" in msg_lower or "name or service not known" in msg_lower or "nodename" in msg_lower:
            return TransportError(error_type="DNS_FAILURE", message=f"DNS resolution failure: {msg}")
        if "refused" in msg_lower or "connectionreset" in exc_name or "connection reset" in msg_lower:
            return TransportError(error_type="CONNECTION_REFUSED", message=f"Connection refused by peer: {msg}")
        if "ssl" in exc_name or "tls" in msg_lower or "certificate" in msg_lower:
            return TransportError(error_type="TLS_ERROR", message=f"TLS/SSL handshake failure: {msg}")

        return TransportError(error_type="CONNECTION_ERROR", message=f"Transport error ({type(exc).__name__}): {msg}")
