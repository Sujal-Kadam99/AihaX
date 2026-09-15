"""Billing and pricing API routes."""

from datetime import datetime, timedelta

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.core.email import send_smtp_email
from backend.models.database import Subscription, get_db
from backend.models.schemas import SubscriptionCreate, SubscriptionResponse
from backend.core.auth import get_current_user
from backend.models.database import User
from backend.core.entitlements import EntitlementManager

router = APIRouter(prefix="/api/billing", tags=["billing"])


class BillingSettings(BaseModel):
    stripe_public_key: str | None = None
    plan_free_trial_scans: int = 3
    plan_pro_monthly: str | None = None
    plan_pro_onetime: str | None = None
    plan_team_monthly: str | None = None
    plan_agency_monthly: str | None = None
    plan_enterprise_monthly: str | None = None


class CreateCheckoutSessionPayload(BaseModel):
    price_id: str
    success_url: str
    cancel_url: str
    email: str | None = None


@router.get("/settings")
async def billing_settings():
    settings = get_settings()
    return BillingSettings(
        stripe_public_key=settings.stripe_public_key,
        plan_pro_monthly=settings.stripe_price_pro_monthly,
        plan_pro_onetime=settings.stripe_price_pro_onetime,
        plan_team_monthly=settings.stripe_price_team_monthly,
        plan_agency_monthly=settings.stripe_price_agency_monthly,
        plan_enterprise_monthly=settings.stripe_price_enterprise_monthly,
    )


@router.post("/session")
async def create_checkout_session(payload: CreateCheckoutSessionPayload):
    settings = get_settings()
    if not settings.stripe_secret_key:
        raise HTTPException(status_code=500, detail="Stripe not configured")

    stripe.api_key = settings.stripe_secret_key
    try:
        is_payment_mode = payload.price_id == settings.stripe_price_pro_onetime
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="payment" if is_payment_mode else "subscription",
            line_items=[
                {"price": payload.price_id, "quantity": 1},
            ],
            success_url=payload.success_url,
            cancel_url=payload.cancel_url,
            customer_email=payload.email,
        )
        return {"url": session.url}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/plans")
async def get_plans():
    settings = get_settings()
    return {
        "plans": [
            {
                "id": settings.stripe_price_pro_monthly,
                "name": "Pro",
                "price": "$29/month",
                "features": ["Unlimited scans", "Full auth testing", "Full report", "Learning"],
            },
            {
                "id": settings.stripe_price_pro_onetime,
                "name": "Pro One-time",
                "price": "$79 one-time",
                "features": ["Unlimited scans", "Full auth testing", "Full report", "Learning"],
            },
            {
                "id": settings.stripe_price_team_monthly,
                "name": "Team",
                "price": "$99/month",
                "features": ["5 seats", "Shared learning DB", "White-label reports"],
            },
            {
                "id": settings.stripe_price_agency_monthly,
                "name": "Agency",
                "price": "$299/month",
                "features": ["Unlimited seats", "Client-branded reports", "Priority support"],
            },
            {
                "id": settings.stripe_price_enterprise_monthly,
                "name": "Enterprise",
                "price": "$999/month",
                "features": ["Self-hosted deployment", "Custom SLA", "Large corporate support"],
            },
        ]
    }


@router.post("/subscriptions/simulate-checkout", response_model=SubscriptionResponse)
async def simulate_checkout(payload: SubscriptionCreate, db: Session = Depends(get_db)):
    # Look for an active subscription for this email
    existing = db.query(Subscription).filter_by(email=payload.email, status="active").first()
    if existing:
        existing.end_date = existing.end_date + timedelta(days=payload.duration_days)
        db.commit()
        db.refresh(existing)
        return existing

    sub = Subscription(
        email=payload.email,
        plan_name=payload.plan_name,
        status="active",
        start_date=datetime.utcnow(),
        end_date=datetime.utcnow() + timedelta(days=payload.duration_days),
    )
    db.add(sub)
    db.commit()
    db.refresh(sub)

    send_smtp_email(
        to_email=payload.email,
        subject="Welcome to AihaX Premium!",
        body=(
            f"Hello,\n\n"
            f"Thank you for choosing AihaX! Your subscription to the "
            f"{payload.plan_name} plan has been activated.\n"
            f"You now have unlimited scans, high fidelity debate auditing, "
            f"and full PDF reporting.\n\n"
            f"Enjoy your security testing!\n\n"
            f"Best regards,\nThe AihaX Team"
        ),
    )
    return sub


@router.get("/subscriptions/list")
async def list_subscriptions(db: Session = Depends(get_db)):
    subs = db.query(Subscription).order_by(Subscription.created_at.desc()).all()
    return subs


class ModifySubscriptionPayload(BaseModel):
    status: str | None = None
    end_date_days_offset: int | None = None


@router.post("/subscriptions/{sub_id}/modify")
async def modify_subscription(
    sub_id: str, payload: ModifySubscriptionPayload, db: Session = Depends(get_db)
):
    sub = db.query(Subscription).filter_by(id=sub_id).first()
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")

    if payload.status:
        sub.status = payload.status

    if payload.end_date_days_offset is not None:
        sub.end_date = datetime.utcnow() + timedelta(days=payload.end_date_days_offset)

    db.commit()
    db.refresh(sub)
    return sub


@router.post("/subscriptions/{sub_id}/notify")
async def trigger_subscription_notify(sub_id: str, db: Session = Depends(get_db)):
    sub = db.query(Subscription).filter_by(id=sub_id).first()
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")

    now = datetime.utcnow()
    sub.last_notified = now
    db.commit()

    end_str = sub.end_date.strftime("%Y-%m-%d %H:%M UTC")
    send_smtp_email(
        to_email=sub.email,
        subject="Reminder: Your AihaX Subscription Ends Soon",
        body=(
            f"Hello,\n\n"
            f"This is a reminder that your subscription to the {sub.plan_name} "
            f"plan ends on {end_str}.\n\n"
            f"Please ensure payment is current to prevent service downgrade.\n\n"
            f"Best regards,\nThe AihaX Team"
        ),
    )
    return {"status": "success", "message": f"Renewal warning email sent to {sub.email}"}

@router.get("/entitlements")
async def get_entitlements(request: Request, db: Session = Depends(get_db)):
    """Fetch the current offline entitlement JWT for the user."""
    from backend.core.auth import get_user_context, _is_local_request
    settings = get_settings()
    user_ctx = get_user_context(request)
    user_email = user_ctx.get("email")
    user_id = user_ctx.get("user_id")

    user = None
    if user_id:
        user = db.query(User).filter_by(id=user_id).first()
    elif user_email:
        user = db.query(User).filter_by(email=user_email).first()

    if not user:
        # Local desktop user or anonymous user
        user = User(
            id=user_id or "local_owner",
            google_sub="local",
            email=user_email or "local@aihax.internal",
            name="Local User"
        )
    
    token = EntitlementManager.generate_entitlement_token(db, user)
    payload = EntitlementManager.verify_entitlement_token(token)
    return {
        "token": token,
        "tier": payload.get("tier", "free"),
        "exp": payload.get("exp")
    }
