"""Configurable rate limiting with exponential backoff for authentication."""

import time
from collections import defaultdict
from threading import Lock
from typing import Literal

from fastapi import HTTPException, Request

from backend.core.config import get_settings

_lock = Lock()

# Timestamps for general rate limiting
# Key format: "public:{ip}" or "authenticated:{token}"
_request_timestamps: dict[str, list[float]] = defaultdict(list)

# Timestamps for scan rate limiting (backwards compatibility)
_scan_timestamps: dict[str, list[float]] = defaultdict(list)

# Auth failures tracking
# Key format: "ip:{ip}" or "user:{username}"
_auth_failures: dict[str, int] = defaultdict(int)
_auth_last_attempt: dict[str, float] = defaultdict(float)

MAX_SCANS_PER_WINDOW = 5
WINDOW_SECONDS = 60


def check_scan_rate_limit(client_id: str = "default") -> None:
    """Allow max 5 scan starts per minute (kept for backwards compatibility)."""
    now = time.time()
    with _lock:
        timestamps = _scan_timestamps[client_id]
        _scan_timestamps[client_id] = [t for t in timestamps if now - t < WINDOW_SECONDS]

        if len(_scan_timestamps[client_id]) >= MAX_SCANS_PER_WINDOW:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: max {MAX_SCANS_PER_WINDOW} scans per minute",
            )

        _scan_timestamps[client_id].append(now)


def _get_client_ip(request: Request) -> str:
    if not request.client:
        return "127.0.0.1"
    return request.client.host or "127.0.0.1"


def check_rate_limit(request: Request, limit_type: Literal["public", "authenticated"]) -> None:
    """Enforce general request rate limits based on endpoint type."""
    settings = get_settings()
    now = time.time()

    if limit_type == "public":
        window = settings.rate_limit_public_window
        max_reqs = settings.rate_limit_public_max_requests
        ip = _get_client_ip(request)
        key = f"public:{ip}"
    else:
        window = settings.rate_limit_authenticated_window
        max_reqs = settings.rate_limit_authenticated_max_requests

        # Try to identify by token, fallback to IP
        from backend.core.auth import extract_token_from_request
        token = extract_token_from_request(request)
        identifier = token if token else _get_client_ip(request)
        key = f"authenticated:{identifier}"

    with _lock:
        timestamps = _request_timestamps[key]
        _request_timestamps[key] = [t for t in timestamps if now - t < window]

        if len(_request_timestamps[key]) >= max_reqs:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: max {max_reqs} requests per {window} seconds",
            )

        _request_timestamps[key].append(now)


def check_auth_rate_limit(request: Request, username: str) -> None:
    """Enforce authentication rate limit with exponential backoff."""
    settings = get_settings()
    ip = _get_client_ip(request)
    now = time.time()

    ip_key = f"ip:{ip}"
    user_key = f"user:{username}"

    with _lock:
        # Determine backoff based on failures
        failures = max(_auth_failures[ip_key], _auth_failures[user_key])
        if failures >= settings.rate_limit_auth_max_attempts:
            # Calculate exponential backoff: base * factor ^ (failures - max_attempts)
            exponent = failures - settings.rate_limit_auth_max_attempts
            backoff_base = settings.rate_limit_auth_backoff_base
            backoff_factor = settings.rate_limit_auth_backoff_factor
            backoff_delay = backoff_base * (backoff_factor**exponent)

            # Find the most recent attempt time
            last_attempt = max(_auth_last_attempt[ip_key], _auth_last_attempt[user_key])
            elapsed = now - last_attempt

            if elapsed < backoff_delay:
                retry_after = int(backoff_delay - elapsed) + 1
                raise HTTPException(
                    status_code=429,
                    detail={
                        "message": (
                            "Too many failed login attempts. Please wait before trying again."
                        ),
                        "retry_after": retry_after,
                        "backoff_delay": int(backoff_delay),
                    },
                )


def record_auth_success(request: Request, username: str) -> None:
    """Reset failures on successful login."""
    ip = _get_client_ip(request)
    ip_key = f"ip:{ip}"
    user_key = f"user:{username}"

    with _lock:
        _auth_failures[ip_key] = 0
        _auth_failures[user_key] = 0
        _auth_last_attempt[ip_key] = 0.0
        _auth_last_attempt[user_key] = 0.0


def record_auth_failure(request: Request, username: str) -> None:
    """Increment failure counters and record attempt timestamps."""
    ip = _get_client_ip(request)
    ip_key = f"ip:{ip}"
    user_key = f"user:{username}"
    now = time.time()

    with _lock:
        _auth_failures[ip_key] += 1
        _auth_failures[user_key] += 1
        _auth_last_attempt[ip_key] = now
        _auth_last_attempt[user_key] = now
