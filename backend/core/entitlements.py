import logging
from datetime import datetime, timezone, timedelta
import jwt
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.core.auth import get_current_user
from backend.models.database import User, Subscription, get_db

logger = logging.getLogger(__name__)
settings = get_settings()

ALGORITHM = "HS256"

# A basic Entitlement Manager for Phase 12 logic.
class EntitlementManager:
    @staticmethod
    def generate_entitlement_token(db: Session, user: User) -> str:
        """
        Generate a signed entitlement JWT based on the user's active subscription.
        Simulates the Cloud Server issuing a JWT to the Desktop Client.
        """
        # Fetch active subscription
        sub = db.query(Subscription).filter(
            Subscription.email == user.email,
            Subscription.status == "active"
        ).first()

        tier = "free"
        if sub:
            plan_name = sub.plan_name.lower()
            if "pro" in plan_name:
                tier = "pro"
            elif "team" in plan_name:
                tier = "team"
            elif "founder" in plan_name:
                tier = "founder"

        # The JWT is valid for 7 days (Offline Grace Period)
        payload = {
            "sub": user.id,
            "email": user.email,
            "tier": tier,
            "exp": datetime.now(timezone.utc) + timedelta(days=7),
            "iat": datetime.now(timezone.utc),
        }

        token = jwt.encode(payload, settings.jwt_secret_key, algorithm=ALGORITHM)
        return token

    @staticmethod
    def verify_entitlement_token(token: str) -> dict:
        """Decode and verify the entitlement JWT."""
        try:
            payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=403, detail="Entitlement token expired (offline grace period exceeded). Please reconnect to the internet.")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=403, detail="Invalid entitlement token.")

# Fastapi Dependency to inject the current user's tier
def get_user_tier(request: Request, db: Session = Depends(get_db)) -> str:
    """
    In a real offline-first app, this would read the locally cached entitlement JWT.
    Since we are bundling SQLite and local backend, we query the DB simulating the cache.
    """
    from backend.core.auth import get_user_context, _is_local_request
    settings = get_settings()
    user_ctx = get_user_context(request)
    user_email = user_ctx.get("email")

    if not user_email:
        if _is_local_request(request):
            return "founder"
        return "free"

    if settings.owner_email and user_email == settings.owner_email:
        return "founder"

    sub = db.query(Subscription).filter(
        Subscription.email == user_email,
        Subscription.status == "active"
    ).first()

    if not sub:
        return "free"

    plan = sub.plan_name.lower()
    if "founder" in plan:
        return "founder"
    elif "team" in plan:
        return "team"
    elif "pro" in plan:
        return "pro"
    
    return "free"


def require_pro(tier: str = Depends(get_user_tier)) -> str:
    """Dependency that requires at least a Pro tier."""
    allowed = {"pro", "team", "founder"}
    if tier not in allowed:
        raise HTTPException(
            status_code=403,
            detail="This feature requires a Pro subscription."
        )
    return tier


def require_team(tier: str = Depends(get_user_tier)) -> str:
    """Dependency that requires at least a Team tier."""
    allowed = {"team", "founder"}
    if tier not in allowed:
        raise HTTPException(
            status_code=403,
            detail="This feature requires a Team subscription."
        )
    return tier
