"""Cloud-issued, locally verifiable subscription entitlements."""

import base64
import json
import logging
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.models.database import EntitlementCache, Subscription, User, get_db

logger = logging.getLogger(__name__)

ALGORITHM = "EdDSA"
AUDIENCE = "aihax-desktop"
OFFLINE_GRACE_DAYS = 7
ALLOWED_TIERS = {"free", "pro", "team", "founder"}


def _key_bytes(value: str) -> bytes:
    """Accept PEM text or base64-encoded PEM from environment configuration."""
    encoded = value.strip()
    if "-----BEGIN" in encoded:
        return encoded.encode("utf-8")
    try:
        return base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise ValueError("Entitlement signing keys must be PEM or base64-encoded PEM") from exc


def _private_key():
    configured_key = get_settings().entitlement_signing_private_key
    if not configured_key:
        raise HTTPException(status_code=503, detail="Entitlement signing is not configured")
    try:
        key = serialization.load_pem_private_key(_key_bytes(configured_key), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Expected an Ed25519 private key")
        return key
    except (TypeError, ValueError) as exc:
        logger.error("Configured entitlement signing key is invalid")
        raise HTTPException(status_code=503, detail="Entitlement signing is unavailable") from exc


def _public_key():
    configured_key = get_settings().entitlement_verification_public_key
    if not configured_key:
        raise HTTPException(status_code=503, detail="Entitlement verification is not configured")
    try:
        key = serialization.load_pem_public_key(_key_bytes(configured_key))
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("Expected an Ed25519 public key")
        return key
    except (TypeError, ValueError) as exc:
        logger.error("Configured entitlement verification key is invalid")
        raise HTTPException(status_code=503, detail="Entitlement verification is unavailable") from exc


class EntitlementManager:
    """Issue entitlements only with a private key; verify with public key only."""

    @staticmethod
    def generate_entitlement_token(db: Session, user: User) -> str:
        now = datetime.now(timezone.utc)
        subscription = (
            db.query(Subscription)
            .filter(
                Subscription.email == user.email,
                Subscription.status == "active",
                Subscription.end_date > now,
            )
            .order_by(Subscription.end_date.desc())
            .first()
        )

        settings = get_settings()
        tier = "free"
        expires_at = now + timedelta(days=OFFLINE_GRACE_DAYS)
        plan_name = "Free"
        if settings.owner_email and user.email.casefold() == settings.owner_email.strip().casefold():
            tier = "founder"
            plan_name = "Founder"
        elif subscription:
            plan_name = subscription.plan_name
            plan = subscription.plan_name.casefold()
            if "founder" in plan:
                tier = "founder"
            elif any(name in plan for name in ("team", "agency", "enterprise")):
                tier = "team"
            elif "pro" in plan:
                tier = "pro"
            # Offline grace can never extend beyond the paid-through date.
            expires_at = min(expires_at, subscription.end_date)

        private_key = _private_key()
        payload = {
            "iss": settings.entitlement_issuer,
            "aud": AUDIENCE,
            "sub": str(user.id),
            "email": user.email,
            "tier": tier,
            "plan": plan_name,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
        }
        return jwt.encode(payload, private_key, algorithm=ALGORITHM)

    @staticmethod
    def verify_entitlement_token(token: str, expected_user_id: str | None = None) -> dict:
        try:
            payload = jwt.decode(
                token,
                _public_key(),
                algorithms=[ALGORITHM],
                audience=AUDIENCE,
                issuer=get_settings().entitlement_issuer,
                options={"require": ["iss", "aud", "sub", "tier", "iat", "exp"]},
            )
            if payload.get("tier") not in ALLOWED_TIERS:
                raise jwt.InvalidTokenError("Invalid entitlement tier")
            if int(payload["exp"]) <= int(payload["iat"]):
                raise jwt.InvalidTokenError("Entitlement expiry is invalid")
            if int(payload["exp"]) - int(payload["iat"]) > OFFLINE_GRACE_DAYS * 24 * 60 * 60:
                raise jwt.InvalidTokenError("Entitlement exceeds the offline grace period")
            if expected_user_id is not None and payload.get("sub") != str(expected_user_id):
                raise jwt.InvalidTokenError("Entitlement belongs to another account")
            return payload
        except jwt.ExpiredSignatureError as exc:
            raise HTTPException(
                status_code=403,
                detail="Entitlement token expired (offline grace period exceeded). Please reconnect to the internet.",
            ) from exc
        except jwt.InvalidTokenError as exc:
            raise HTTPException(status_code=403, detail="Invalid entitlement token.") from exc

    @staticmethod
    def cache_entitlement(db: Session, token: str, payload: dict) -> EntitlementCache:
        user_id = str(payload["sub"])
        cache = db.query(EntitlementCache).filter_by(user_id=user_id).first()
        if not cache:
            cache = EntitlementCache(user_id=user_id, plan_name=payload["plan"], entitlement_jwt=token,
                                     expires_at=datetime.fromtimestamp(payload["exp"], timezone.utc))
            db.add(cache)
        else:
            cache.plan_name = payload["plan"]
            cache.entitlement_jwt = token
            cache.expires_at = datetime.fromtimestamp(payload["exp"], timezone.utc)
            cache.synced_at = datetime.now(timezone.utc)
        cache.features_json = json.dumps({"tier": payload["tier"]}, sort_keys=True)
        db.commit()
        db.refresh(cache)
        return cache


def get_user_tier(request: Request, db: Session = Depends(get_db)) -> str:
    """Use only a valid signed entitlement cached for the authenticated user."""
    from backend.core.auth import get_user_context

    user_ctx = get_user_context(request)
    user_id = user_ctx.get("user_id")
    if not user_id:
        return "free"

    cache = db.query(EntitlementCache).filter_by(user_id=str(user_id)).first()
    if not cache:
        return "free"
    try:
        payload = EntitlementManager.verify_entitlement_token(
            cache.entitlement_jwt, expected_user_id=str(user_id)
        )
    except HTTPException:
        logger.warning("Ignoring invalid or expired cached entitlement for user %s", user_id)
        return "free"
    return payload["tier"]


def require_pro(tier: str = Depends(get_user_tier)) -> str:
    """Dependency that requires at least a Pro tier."""
    if tier not in {"pro", "team", "founder"}:
        raise HTTPException(status_code=403, detail="This feature requires a Pro subscription.")
    return tier


def require_team(tier: str = Depends(get_user_tier)) -> str:
    """Dependency that requires at least a Team tier."""
    if tier not in {"team", "founder"}:
        raise HTTPException(status_code=403, detail="This feature requires a Team subscription.")
    return tier
