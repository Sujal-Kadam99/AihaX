"""Authentication core module for AihaX: Local IPC Security + Google OIDC Identity + Session JWTs."""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import jwt
import requests
from fastapi import Depends, HTTPException, Request, WebSocket
from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.models.database import RefreshToken, User, get_db

TOKEN_FILENAME = ".api_token"
PUBLIC_PATHS = {
    "/api/health",
    "/api/auth/google/login",
    "/api/auth/refresh",
    "/api/billing/webhook",  # Stripe authenticates this route with its signature header.
}
PUBLIC_PREFIXES: set[str] = set()
TOKEN_PATH = "/api/auth/token"
LOCAL_ONLY_PATHS = {"/api/auth/token", "/api/auth/admin", "/api/auth/admin/verify", "/openapi.json"}
LOCAL_ONLY_PREFIXES = {"/docs", "/redoc"}
LOCAL_HOSTS = {"127.0.0.1", "::1"}


def _augment_local_hosts() -> None:
    """Auto-detect Docker Desktop gateway IPs and add them to LOCAL_HOSTS."""
    common_docker_gateways = [
        "172.17.0.1",
        "172.18.0.1",
        "172.19.0.1",
        "172.20.0.1",
        "172.21.0.1",
        "172.22.0.1",
        "172.23.0.1",
        "172.24.0.1",
        "172.25.0.1",
        "172.26.0.1",
        "172.27.0.1",
        "172.28.0.1",
        "172.29.0.1",
        "172.30.0.1",
        "172.31.0.1",
        "192.168.65.1",
        "192.168.244.1",
        "192.168.65.254",
    ]
    try:
        hostname = socket.gethostname()
        for _, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            ip = str(sockaddr[0])
            if ip.startswith("172.") or ip.startswith("192.168.") or ip.startswith("10."):
                LOCAL_HOSTS.add(ip)
    except Exception:
        pass

    for ip in common_docker_gateways:
        LOCAL_HOSTS.add(ip)


_augment_local_hosts()


# -----------------------------------------------------------------------------
# Local IPC Token Management (Desktop Process Boundary)
# -----------------------------------------------------------------------------

def _token_path() -> Path:
    settings = get_settings()
    return Path(settings.config_path) / TOKEN_FILENAME


def get_or_create_api_token() -> str:
    """Load existing token or generate a new one on first run."""
    path = _token_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        token = path.read_text().strip()
        if token:
            return token

    token = secrets.token_urlsafe(32)
    path.write_text(token)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return token


def validate_token(token: str | None) -> bool:
    if not token:
        return False
    expected = get_or_create_api_token()
    return secrets.compare_digest(token, expected)


def extract_token_from_request(request: Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.headers.get("X-AihaX-Token")


def get_user_context(request: Request) -> dict[str, str | None]:
    """Extract user identity (user_id, email) from the request token if available.

    Returns {"user_id": None, "email": None} for local IPC tokens or
    unauthenticated requests.
    """
    token = extract_token_from_request(request)
    if not token:
        return {"user_id": None, "email": None}
    try:
        payload = _decode_user_access_token(token)
        return {
            "user_id": payload.get("sub"),
            "email": payload.get("email"),
        }
    except Exception:
        return {"user_id": None, "email": None}


def _is_local_request(request: Request) -> bool:
    if not request.client:
        print("DEBUG_LOCAL_AUTH: No request.client")
        return False
    host = request.client.host or ""
    print(f"DEBUG_LOCAL_AUTH: Incoming host is {host}")
    if (
        host in LOCAL_HOSTS
        or host.startswith("::ffff:127.0.0.1")
        or host.startswith("172.")
        or host.startswith("192.168.")
        or host.startswith("10.")
    ):
        return True
    return False


def _is_public_path(path: str) -> bool:
    return path in PUBLIC_PATHS


def _is_local_only_path(path: str) -> bool:
    if path in LOCAL_ONLY_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in LOCAL_ONLY_PREFIXES)


def require_auth(request: Request) -> None:
    path = request.url.path

    if _is_local_only_path(path):
        if not _is_local_request(request):
            raise HTTPException(status_code=403, detail="This endpoint is restricted to localhost")
        return

    if _is_public_path(path):
        return

    token = extract_token_from_request(request)
    if not validate_token(token):
        # Also check if it's a valid User Session JWT
        try:
            if token and _decode_user_access_token(token):
                return
        except Exception:
            pass
        raise HTTPException(status_code=401, detail="Invalid or missing authentication token")


async def require_ws_auth(websocket: WebSocket, scan_id: str) -> bool:
    token = websocket.query_params.get("token")
    if not validate_token(token):
        await websocket.close(code=1008, reason="Unauthorized")
        return False
    return True


async def require_ws_auth_token(token: str, scan_id: str) -> bool:
    """Validate WebSocket auth token received as first message (not in URL)."""
    return validate_token(token)


# -----------------------------------------------------------------------------
# Google OIDC Verification & Identity Boundary
# -----------------------------------------------------------------------------

def verify_google_id_token(id_token_str: str) -> dict[str, Any]:
    """Verify Google OIDC ID token assertion. Return extracted claims dict."""
    settings = get_settings()

    # Safety Check: Gated Dev Mock Auth (Strictly forbidden in production/cloud)
    if settings.dev_mock_auth:
        if settings.environment.lower() in ("production", "cloud"):
            raise RuntimeError("FATAL: DEV_MOCK_AUTH cannot be used in production or cloud environment")
        if id_token_str.startswith("mock_id_token_"):
            mock_sub = id_token_str.replace("mock_id_token_", "") or "dev_mock_sub_12345"
            return {
                "sub": f"google_sub_{mock_sub}",
                "email": f"{mock_sub}@example.com",
                "email_verified": True,
                "name": f"Dev User {mock_sub}",
                "picture": "https://via.placeholder.com/150",
            }

    if not id_token_str:
        raise HTTPException(status_code=400, detail="Missing Google ID token")

    try:
        # Validate via Google TokenInfo API Endpoint
        resp = requests.get(
            f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token_str}",
            timeout=10,
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Google ID token verification failed")

        data = resp.json()
        iss = data.get("iss", "")
        if iss not in ("https://accounts.google.com", "accounts.google.com"):
            raise HTTPException(status_code=401, detail="Invalid token issuer")

        if settings.google_client_id and data.get("aud") != settings.google_client_id:
            raise HTTPException(status_code=401, detail="Invalid token audience")

        verified_email = data.get("email_verified", data.get("verified_email"))
        if verified_email is not True and str(verified_email).casefold() != "true":
            raise HTTPException(status_code=401, detail="Google account email is not verified")

        exp = int(data.get("exp", 0))
        now_ts = int(datetime.now(timezone.utc).timestamp())
        if exp < now_ts:
            raise HTTPException(status_code=401, detail="Google ID token has expired")

        google_sub = data.get("sub")
        email = data.get("email")
        if not google_sub or not email:
            raise HTTPException(status_code=401, detail="Malformed Google ID token missing sub or email")

        return {
            "sub": str(google_sub),
            "email": str(email),
            "email_verified": True,
            "name": data.get("name", email.split("@")[0]),
            "picture": data.get("picture"),
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"Failed to verify Google ID token: {str(exc)}")


# -----------------------------------------------------------------------------
# AihaX Session JWT & Rotated Refresh Token Management
# -----------------------------------------------------------------------------

def create_user_access_token(user: User) -> str:
    """Issue short-lived 15-minute AihaX Access JWT."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=settings.access_token_expire_minutes)

    payload = {
        "sub": str(user.id),
        "google_sub": str(user.google_sub),
        "email": str(user.email),
        "jti": str(uuid.uuid4()),
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def _decode_user_access_token(token_str: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token_str, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
        )
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Access token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid access token signature")


def create_user_refresh_token(
    db: Session, user: User, family_id: str | None = None
) -> tuple[str, RefreshToken]:
    """Generate high-entropy refresh token, store SHA-256 hash in DB, return raw token."""
    settings = get_settings()
    raw_token = secrets.token_hex(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    if not family_id:
        family_id = str(uuid.uuid4())

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=settings.refresh_token_expire_days)

    db_token = RefreshToken(
        id=str(uuid.uuid4()),
        user_id=str(user.id),
        token_hash=token_hash,
        family_id=family_id,
        revoked=False,
        expires_at=expires_at,
        created_at=now,
    )
    db.add(db_token)
    db.commit()
    db.refresh(db_token)
    return raw_token, db_token


import threading

_rotation_lock = threading.Lock()


def verify_and_rotate_refresh_token(
    db: Session, raw_token_str: str
) -> tuple[str, str, User]:
    """Validate refresh token with atomic DB rotation and token family reuse detection."""
    if not raw_token_str:
        raise HTTPException(status_code=400, detail="Missing refresh token")

    with _rotation_lock:
        token_hash = hashlib.sha256(raw_token_str.encode()).hexdigest()
        now_utc = datetime.now(timezone.utc)

        # ATOMIC CONCURRENCY GUARD: Attempt single-statement update for unrevoked & non-expired token
        updated_count = (
            db.query(RefreshToken)
            .filter(
                RefreshToken.token_hash == token_hash,
                RefreshToken.revoked.is_(False),
                RefreshToken.expires_at > now_utc,
            )
            .update({"revoked": True}, synchronize_session=False)
        )
        db.commit()

    if updated_count == 0:
        # Atomic update failed: Query record to diagnose if missing, expired, or ALREADY REVOKED (REUSE DETECTED!)
        token_record = db.query(RefreshToken).filter_by(token_hash=token_hash).first()
        if not token_record:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        if token_record.expires_at < now_utc:
            if not token_record.revoked:
                token_record.revoked = True  # type: ignore
                db.commit()
            raise HTTPException(status_code=401, detail="Refresh token has expired")

        if token_record.revoked:
            # REUSE DETECTED: Revoke entire token family immediately!
            db.query(RefreshToken).filter_by(family_id=token_record.family_id).update({"revoked": True})
            db.commit()
            raise HTTPException(
                status_code=401,
                detail="Revoked refresh token reuse detected. Entire session family revoked for security.",
            )

    # Fetch token record after successful atomic update
    token_record = db.query(RefreshToken).filter_by(token_hash=token_hash).first()
    if not token_record:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # Retrieve associated User
    user = db.query(User).filter_by(id=token_record.user_id).first()
    if not user or user.account_status != "active":
        raise HTTPException(status_code=403, detail="Account is disabled or suspended")

    # Issue new Access Token and rotated Refresh Token under same family_id
    new_access_token = create_user_access_token(user)
    new_raw_refresh_token, _ = create_user_refresh_token(db, user, family_id=str(token_record.family_id))

    return new_access_token, new_raw_refresh_token, user


def revoke_user_session(db: Session, raw_token_str: str) -> bool:
    """Revoke specific refresh token on logout."""
    if not raw_token_str:
        return False
    token_hash = hashlib.sha256(raw_token_str.encode()).hexdigest()
    token_record = db.query(RefreshToken).filter_by(token_hash=token_hash).first()
    if token_record:
        token_record.revoked = True  # type: ignore
        db.commit()
        return True
    return False


# -----------------------------------------------------------------------------
# FastAPI User Authorization Dependency
# -----------------------------------------------------------------------------

def get_current_user(
    request: Request, db: Session = Depends(get_db)
) -> User:
    """FastAPI Dependency enforcing authenticated User context."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Bearer authorization header")

    token_str = auth_header[7:]
    payload = _decode_user_access_token(token_str)
    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token subject")

    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User account not found")

    if user.account_status != "active":
        raise HTTPException(status_code=403, detail="Account has been disabled or suspended")

    return user


def get_current_user_optional(
    request: Request, db: Session = Depends(get_db)
) -> Optional[User]:
    """FastAPI Dependency returning current User if valid Bearer token present, else None."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    try:
        token_str = auth_header[7:]
        payload = _decode_user_access_token(token_str)
        user_id = payload.get("sub")
        if not user_id:
            return None
        user = db.query(User).filter_by(id=user_id).first()
        if user and user.account_status == "active":
            return user
    except Exception:
        pass
    return None

