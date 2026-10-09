"""Billing and pricing API routes."""

from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.core.email import send_smtp_email
from backend.models.database import StripeWebhookEvent, Subscription, User, get_db
from backend.models.schemas import SubscriptionCreate, SubscriptionResponse
from backend.core.auth import get_current_user
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


def _configured_plans(settings) -> dict[str, str]:
    """Return the only Stripe price IDs this product is allowed to sell."""
    return {
        price_id: name
        for price_id, name in (
            (settings.stripe_price_pro_monthly, "Pro"),
            (settings.stripe_price_pro_onetime, "Pro One-time"),
            (settings.stripe_price_team_monthly, "Team"),
            (settings.stripe_price_agency_monthly, "Agency"),
            (settings.stripe_price_enterprise_monthly, "Enterprise"),
        )
        if price_id
    }


def _stripe_value(obj, name: str, default=None):
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def require_billing_admin(current_user: User = Depends(get_current_user)) -> User:
    """Restrict subscription administration to the configured account owner."""
    owner_email = (get_settings().owner_email or "").strip().casefold()
    if not owner_email or current_user.email.strip().casefold() != owner_email:
        raise HTTPException(status_code=403, detail="Billing administration is restricted")
    return current_user


def _validate_return_url(url: str, settings) -> None:
    parsed = urlsplit(url)
    if not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="Invalid checkout return URL")
    is_loopback = parsed.hostname.lower() in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and is_loopback):
        raise HTTPException(status_code=400, detail="Checkout return URLs must use HTTPS")

    allowed_origins = {
        value.strip().rstrip("/").lower()
        for value in getattr(settings, "billing_return_origins", "").split(",")
        if value.strip()
    }
    if not allowed_origins and getattr(settings, "environment", "local").lower() == "local":
        allowed_origins = {
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        }
    if not allowed_origins:
        raise HTTPException(status_code=503, detail="Checkout return origins are not configured")

    origin = f"{parsed.scheme}://{parsed.netloc}".lower()
    if origin not in allowed_origins:
        raise HTTPException(status_code=400, detail="Checkout return URL origin is not allowed")


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
async def create_checkout_session(
    payload: CreateCheckoutSessionPayload,
    current_user: User = Depends(get_current_user),
):
    settings = get_settings()
    if not settings.stripe_secret_key:
        raise HTTPException(status_code=500, detail="Stripe not configured")

    # Never let a client choose arbitrary prices from the Stripe account. The
    # browser receives these IDs from /plans, but that is not an authorization
    # boundary: validate them again before creating a paid session.
    plan_name = _configured_plans(settings).get(payload.price_id)
    if not plan_name:
        raise HTTPException(status_code=400, detail="Unknown or unavailable plan")
    _validate_return_url(payload.success_url, settings)
    _validate_return_url(payload.cancel_url, settings)

    stripe.api_key = settings.stripe_secret_key
    try:
        is_payment_mode = payload.price_id == settings.stripe_price_pro_onetime
        metadata = {
            "user_id": current_user.id,
            "plan_name": plan_name,
            "price_id": payload.price_id,
        }
        session_args = dict(
            payment_method_types=["card"],
            mode="payment" if is_payment_mode else "subscription",
            line_items=[
                {"price": payload.price_id, "quantity": 1},
            ],
            success_url=payload.success_url,
            cancel_url=payload.cancel_url,
            customer_email=current_user.email,
            client_reference_id=current_user.id,
            metadata=metadata,
        )
        if not is_payment_mode:
            session_args["subscription_data"] = {"metadata": metadata}
        session = stripe.checkout.Session.create(**session_args)
        return {"url": session.url}
    except Exception as exc:
        # Avoid returning provider diagnostics, which can contain account or
        # request details, to the client.
        raise HTTPException(status_code=502, detail="Unable to create checkout session") from exc


@router.post("/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    """Verify Stripe signatures and apply payment/subscription state idempotently."""
    settings = get_settings()
    if not settings.stripe_webhook_secret or not settings.stripe_secret_key:
        raise HTTPException(status_code=503, detail="Stripe webhooks are not configured")

    signature = request.headers.get("stripe-signature")
    if not signature:
        raise HTTPException(status_code=400, detail="Missing Stripe signature")
    try:
        event = stripe.Webhook.construct_event(
            await request.body(), signature, settings.stripe_webhook_secret
        )
    except Exception as exc:
        # Stripe's signature exception type differs between SDK versions; all
        # construction failures are rejected without echoing provider details.
        raise HTTPException(status_code=400, detail="Invalid Stripe webhook") from exc

    event_id = _stripe_value(event, "id")
    event_type = _stripe_value(event, "type")
    data = _stripe_value(event, "data", {})
    obj = _stripe_value(data, "object", {})
    if not event_id or not event_type:
        raise HTTPException(status_code=400, detail="Malformed Stripe event")

    if db.query(StripeWebhookEvent).filter_by(event_id=event_id).first():
        return {"received": True, "duplicate": True}

    stripe.api_key = settings.stripe_secret_key
    now = datetime.now(timezone.utc)

    if event_type in ("checkout.session.completed", "checkout.session.async_payment_succeeded"):
        payment_status = _stripe_value(obj, "payment_status")
        if payment_status not in ("paid", "no_payment_required"):
            return {"received": True, "ignored": True}

        metadata = _stripe_value(obj, "metadata", {}) or {}
        user_id = _stripe_value(obj, "client_reference_id") or _stripe_value(metadata, "user_id")
        price_id = _stripe_value(metadata, "price_id")
        plan_name = _configured_plans(settings).get(price_id)
        user = db.query(User).filter_by(id=user_id).first() if user_id else None
        if not user or not plan_name or _stripe_value(metadata, "plan_name") != plan_name:
            raise HTTPException(status_code=400, detail="Checkout metadata is invalid")

        mode = _stripe_value(obj, "mode")
        subscription_id = _stripe_value(obj, "subscription")
        status = "active"
        if mode == "subscription":
            if not subscription_id:
                raise HTTPException(status_code=400, detail="Subscription reference is missing")
            try:
                stripe_subscription = stripe.Subscription.retrieve(subscription_id)
            except Exception as exc:
                raise HTTPException(status_code=502, detail="Unable to verify subscription") from exc
            provider_status = _stripe_value(stripe_subscription, "status", "")
            period_end = _stripe_value(stripe_subscription, "current_period_end")
            if provider_status not in ("active", "trialing") or not period_end:
                return {"received": True, "ignored": True}
            status = "active"
            end_date = datetime.fromtimestamp(period_end, timezone.utc)
        elif mode == "payment":
            end_date = now + timedelta(days=36500)
        else:
            raise HTTPException(status_code=400, detail="Unsupported checkout mode")

        checkout_id = _stripe_value(obj, "id")
        subscription = None
        if subscription_id:
            subscription = db.query(Subscription).filter_by(
                stripe_subscription_id=subscription_id
            ).first()
        if not subscription and checkout_id:
            subscription = db.query(Subscription).filter_by(
                stripe_checkout_session_id=checkout_id
            ).first()
        if not subscription:
            subscription = Subscription(
                email=user.email,
                plan_name=plan_name,
                start_date=now,
                end_date=end_date,
            )
            db.add(subscription)
        subscription.email = user.email
        subscription.plan_name = plan_name
        subscription.status = status
        subscription.start_date = now
        subscription.end_date = end_date
        subscription.stripe_subscription_id = subscription_id
        subscription.stripe_customer_id = _stripe_value(obj, "customer")
        subscription.stripe_checkout_session_id = checkout_id

    elif event_type in ("customer.subscription.updated", "customer.subscription.deleted"):
        subscription_id = _stripe_value(obj, "id")
        subscription = db.query(Subscription).filter_by(
            stripe_subscription_id=subscription_id
        ).first()
        if subscription:
            status = _stripe_value(obj, "status", "canceled")
            if event_type == "customer.subscription.deleted":
                status = "canceled"
            elif status == "trialing":
                status = "active"
            subscription.status = status
            period_end = _stripe_value(obj, "current_period_end")
            if period_end:
                subscription.end_date = datetime.fromtimestamp(period_end, timezone.utc)

    elif event_type in ("invoice.payment_failed", "invoice.paid"):
        invoice_subscription = _stripe_value(obj, "subscription")
        if invoice_subscription and not isinstance(invoice_subscription, str):
            invoice_subscription = _stripe_value(invoice_subscription, "id")
        if invoice_subscription:
            subscription = db.query(Subscription).filter_by(
                stripe_subscription_id=invoice_subscription
            ).first()
            if subscription:
                if event_type == "invoice.payment_failed":
                    subscription.status = "past_due"
                else:
                    try:
                        provider_subscription = stripe.Subscription.retrieve(invoice_subscription)
                    except Exception as exc:
                        raise HTTPException(
                            status_code=502, detail="Unable to verify subscription"
                        ) from exc
                    provider_status = _stripe_value(provider_subscription, "status", "")
                    if provider_status in ("active", "trialing"):
                        subscription.status = "active"
                        period_end = _stripe_value(provider_subscription, "current_period_end")
                        if period_end:
                            subscription.end_date = datetime.fromtimestamp(
                                period_end, timezone.utc
                            )

    db.add(StripeWebhookEvent(event_id=event_id, event_type=event_type, received_at=now))
    try:
        db.commit()
    except Exception:
        db.rollback()
        # Concurrent Stripe retries can race on the unique event ID. Let Stripe
        # retry; the next delivery will observe the committed event record.
        raise HTTPException(status_code=503, detail="Unable to record Stripe event")
    return {"received": True, "duplicate": False}


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
async def simulate_checkout(
    payload: SubscriptionCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    settings = get_settings()
    if not settings.dev_mock_billing or settings.environment.lower() != "local":
        raise HTTPException(status_code=403, detail="Simulated checkout is disabled")

    plan_name = payload.plan_name.strip()
    supported_plans = {"pro", "pro one-time", "team", "agency", "enterprise"}
    if plan_name.casefold() not in supported_plans:
        raise HTTPException(status_code=400, detail="Unknown or unavailable plan")
    if payload.duration_days < 1 or payload.duration_days > 3650:
        raise HTTPException(status_code=400, detail="Invalid subscription duration")

    # Development-only simulations still bind the subscription to the
    # authenticated account. The request body cannot grant a tier to another
    # email address.
    user_email = current_user.email
    now = datetime.now(timezone.utc)
    existing = db.query(Subscription).filter_by(email=user_email, status="active").first()
    if existing:
        existing.plan_name = plan_name
        existing.end_date = max(existing.end_date, now) + timedelta(days=payload.duration_days)
        db.commit()
        db.refresh(existing)
        return existing

    sub = Subscription(
        email=user_email,
        plan_name=plan_name,
        status="active",
        start_date=now,
        end_date=now + timedelta(days=payload.duration_days),
    )
    db.add(sub)
    db.commit()
    db.refresh(sub)

    send_smtp_email(
        to_email=user_email,
        subject="Welcome to AihaX Premium!",
        body=(
            f"Hello,\n\n"
            f"Thank you for choosing AihaX! Your subscription to the "
            f"{plan_name} plan has been activated.\n"
            f"You now have unlimited scans, high fidelity debate auditing, "
            f"and full PDF reporting.\n\n"
            f"Enjoy your security testing!\n\n"
            f"Best regards,\nThe AihaX Team"
        ),
    )
    return sub


@router.get("/subscriptions/list")
async def list_subscriptions(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_billing_admin),
):
    subs = db.query(Subscription).order_by(Subscription.created_at.desc()).all()
    return subs


class ModifySubscriptionPayload(BaseModel):
    status: str | None = None
    end_date_days_offset: int | None = None


@router.post("/subscriptions/{sub_id}/modify")
async def modify_subscription(
    sub_id: str,
    payload: ModifySubscriptionPayload,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_billing_admin),
):
    sub = db.query(Subscription).filter_by(id=sub_id).first()
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")

    if payload.status:
        sub.status = payload.status

    if payload.end_date_days_offset is not None:
        sub.end_date = datetime.now(timezone.utc) + timedelta(days=payload.end_date_days_offset)

    db.commit()
    db.refresh(sub)
    return sub


@router.post("/subscriptions/{sub_id}/notify")
async def trigger_subscription_notify(
    sub_id: str,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_billing_admin),
):
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
async def get_entitlements(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Issue and persist a cloud-signed offline entitlement for this account."""
    token = EntitlementManager.generate_entitlement_token(db, current_user)
    payload = EntitlementManager.verify_entitlement_token(token, expected_user_id=current_user.id)
    EntitlementManager.cache_entitlement(db, token, payload)
    return {
        "token": token,
        "tier": payload.get("tier", "free"),
        "exp": payload.get("exp")
    }
