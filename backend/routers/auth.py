"""Authentication routes: Local API token IPC + Google OIDC Identity & Sessions."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend.core.auth import (
    _is_local_request,
    create_user_access_token,
    create_user_refresh_token,
    get_current_user,
    get_or_create_api_token,
    revoke_user_session,
    verify_and_rotate_refresh_token,
    verify_google_id_token,
)
from backend.core.config import get_settings
from backend.core.rate_limit import (
    check_auth_rate_limit,
    record_auth_failure,
    record_auth_success,
)
from backend.models.database import User, get_db
from backend.models.schemas import (
    AuthSessionResponse,
    CredentialPair,
    GoogleLoginPayload,
    TokenRefreshPayload,
    UserResponse,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


# -----------------------------------------------------------------------------
# Google OAuth2 / OIDC Identity & Session Endpoints
# -----------------------------------------------------------------------------

@router.post("/google/login", response_model=AuthSessionResponse)
async def google_login(payload: GoogleLoginPayload, request: Request, db: Session = Depends(get_db)):
    """Authenticate Google OIDC ID token assertion, lookup/create User, issue session JWT."""
    check_auth_rate_limit(request, "google_login")

    # 1. Verify Google OIDC Identity assertion
    claims = verify_google_id_token(payload.id_token)
    google_sub = claims["sub"]
    email = claims["email"]

    # 2. Lookup or create User by immutable google_sub
    user = db.query(User).filter_by(google_sub=google_sub).first()
    if not user:
        # Check if user exists by email (to bind google_sub)
        user = db.query(User).filter_by(email=email).first()
        if user:
            user.google_sub = google_sub
            user.name = claims.get("name") or user.name
            user.picture = claims.get("picture") or user.picture
            user.email_verified = claims.get("email_verified", True)
            user.last_login_at = datetime.now(timezone.utc)
        else:
            user = User(
                google_sub=google_sub,
                email=email,
                email_verified=claims.get("email_verified", True),
                name=claims.get("name"),
                picture=claims.get("picture"),
                account_status="active",
                created_at=datetime.now(timezone.utc),
                last_login_at=datetime.now(timezone.utc),
            )
            db.add(user)
    else:
        user.last_login_at = datetime.now(timezone.utc)
        if claims.get("name"):
            user.name = claims.get("name")
        if claims.get("picture"):
            user.picture = claims.get("picture")

    if user.account_status != "active":
        record_auth_failure(request, email)
        raise HTTPException(status_code=403, detail="Account has been disabled or suspended")

    db.commit()
    db.refresh(user)
    record_auth_success(request, email)

    # 3. Mint short-lived Access JWT & rotated Refresh Token
    settings = get_settings()
    access_token = create_user_access_token(user)
    raw_refresh_token, _ = create_user_refresh_token(db, user)

    user_resp = UserResponse(
        id=user.id,
        google_sub=user.google_sub,
        email=user.email,
        email_verified=user.email_verified,
        name=user.name,
        picture=user.picture,
        account_status=user.account_status,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )

    return AuthSessionResponse(
        access_token=access_token,
        refresh_token=raw_refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
        token_type="Bearer",
        user=user_resp,
    )


@router.post("/refresh", response_model=AuthSessionResponse)
async def refresh_token_endpoint(
    payload: TokenRefreshPayload, request: Request, db: Session = Depends(get_db)
):
    """Verify refresh token, execute automatic rotation, and check token family reuse."""
    check_auth_rate_limit(request, "refresh_token")

    access_token, new_refresh_token, user = verify_and_rotate_refresh_token(
        db, payload.refresh_token
    )
    settings = get_settings()

    user_resp = UserResponse(
        id=user.id,
        google_sub=user.google_sub,
        email=user.email,
        email_verified=user.email_verified,
        name=user.name,
        picture=user.picture,
        account_status=user.account_status,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )

    return AuthSessionResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
        token_type="Bearer",
        user=user_resp,
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Return authenticated user profile."""
    return UserResponse(
        id=current_user.id,
        google_sub=current_user.google_sub,
        email=current_user.email,
        email_verified=current_user.email_verified,
        name=current_user.name,
        picture=current_user.picture,
        account_status=current_user.account_status,
        created_at=current_user.created_at,
        last_login_at=current_user.last_login_at,
    )


@router.post("/logout")
async def logout_endpoint(
    payload: TokenRefreshPayload | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke user session and refresh token."""
    if payload and payload.refresh_token:
        revoke_user_session(db, payload.refresh_token)
    return {"success": True, "message": "Successfully logged out"}


# -----------------------------------------------------------------------------
# Local IPC Desktop Endpoints (Restricted to localhost)
# -----------------------------------------------------------------------------

@router.get("/token")
async def get_api_token(request: Request):
    """Return the local API token. Only reachable when bound to localhost."""
    if not _is_local_request(request):
        raise HTTPException(status_code=403, detail="Token retrieval is restricted to localhost")
    return {"token": get_or_create_api_token()}


@router.get("/admin")
async def get_admin_credentials(request: Request):
    """Return local administrative parameters. Restricted to localhost."""
    if not _is_local_request(request):
        raise HTTPException(
            status_code=403, detail="Admin credentials retrieval is restricted to localhost"
        )
    return {"status": "active", "auth_provider": "google"}


@router.post("/admin/verify")
async def verify_admin_credentials(payload: CredentialPair, request: Request):
    """Legacy admin endpoint check. Restricted to localhost."""
    if not _is_local_request(request):
        raise HTTPException(
            status_code=403, detail="Admin credentials verification is restricted to localhost"
        )
    check_auth_rate_limit(request, payload.username)
    record_auth_success(request, payload.username)
    return {"status": "success", "token": get_or_create_api_token()}
