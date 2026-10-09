import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import jwt
from fastapi import HTTPException
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

from backend.core.auth import require_auth
from backend.core.entitlements import EntitlementManager
from backend.models.database import Base, StripeWebhookEvent, Subscription, User
from backend.models.migrations import MIGRATIONS, _compute_checksum, run_migrations
from backend.models.schemas import SubscriptionCreate
from backend.routers import billing


@pytest.fixture
def billing_settings():
    return SimpleNamespace(
        stripe_secret_key="sk_test_placeholder",
        stripe_webhook_secret="whsec_test_placeholder",
        dev_mock_billing=False,
        environment="local",
        stripe_price_pro_monthly="price_pro_monthly",
        stripe_price_pro_onetime="price_pro_once",
        stripe_price_team_monthly="price_team",
        stripe_price_agency_monthly="price_agency",
        stripe_price_enterprise_monthly="price_enterprise",
    )


@pytest.fixture
def checkout_payload():
    return billing.CreateCheckoutSessionPayload(
        price_id="price_pro_monthly",
        success_url="http://localhost:3000/success",
        cancel_url="http://localhost:3000/cancel",
        email="spoofed@example.test",
    )


@pytest.fixture
def buyer():
    return User(id="user-123", email="buyer@example.test", google_sub="google-user-123")


def test_billing_admin_requires_configured_owner_account(buyer):
    settings = SimpleNamespace(owner_email="owner@example.test")
    with patch.object(billing, "get_settings", return_value=settings):
        with pytest.raises(HTTPException) as exc_info:
            billing.require_billing_admin(current_user=buyer)

    assert exc_info.value.status_code == 403


def test_billing_admin_accepts_configured_owner_case_insensitively():
    owner = User(id="owner-123", email="Owner@Example.Test", google_sub="owner-google")
    settings = SimpleNamespace(owner_email="owner@example.test")
    with patch.object(billing, "get_settings", return_value=settings):
        assert billing.require_billing_admin(current_user=owner) is owner


def test_billing_admin_fails_closed_without_configured_owner(buyer):
    settings = SimpleNamespace(owner_email="")
    with patch.object(billing, "get_settings", return_value=settings):
        with pytest.raises(HTTPException) as exc_info:
            billing.require_billing_admin(current_user=buyer)

    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_checkout_uses_configured_price_and_authenticated_email(
    billing_settings, checkout_payload, buyer
):
    with (
        patch.object(billing, "get_settings", return_value=billing_settings),
        patch.object(
            billing.stripe.checkout.Session,
            "create",
            return_value=SimpleNamespace(url="https://checkout.stripe.test/session"),
        ) as stripe_create,
    ):
        result = await billing.create_checkout_session(checkout_payload, current_user=buyer)

    assert result["url"] == "https://checkout.stripe.test/session"
    assert stripe_create.call_args.kwargs["line_items"] == [
        {"price": "price_pro_monthly", "quantity": 1}
    ]
    assert stripe_create.call_args.kwargs["customer_email"] == buyer.email


@pytest.mark.asyncio
async def test_checkout_rejects_unconfigured_price_before_stripe_call(
    billing_settings, checkout_payload, buyer
):
    checkout_payload.price_id = "price_not_configured"
    with (
        patch.object(billing, "get_settings", return_value=billing_settings),
        patch.object(billing.stripe.checkout.Session, "create") as stripe_create,
    ):
        with pytest.raises(HTTPException) as exc_info:
            await billing.create_checkout_session(checkout_payload, current_user=buyer)

    assert exc_info.value.status_code == 400
    stripe_create.assert_not_called()


@pytest.mark.asyncio
async def test_checkout_rejects_untrusted_return_origin(billing_settings, checkout_payload, buyer):
    checkout_payload.success_url = "https://attacker.example/collect"
    with (
        patch.object(billing, "get_settings", return_value=billing_settings),
        patch.object(billing.stripe.checkout.Session, "create") as stripe_create,
    ):
        with pytest.raises(HTTPException) as exc_info:
            await billing.create_checkout_session(checkout_payload, current_user=buyer)

    assert exc_info.value.status_code == 400
    stripe_create.assert_not_called()


@pytest.mark.asyncio
async def test_cloud_checkout_requires_explicit_return_origin(
    billing_settings, checkout_payload, buyer
):
    billing_settings.environment = "cloud"
    with (
        patch.object(billing, "get_settings", return_value=billing_settings),
        patch.object(billing.stripe.checkout.Session, "create") as stripe_create,
    ):
        with pytest.raises(HTTPException) as exc_info:
            await billing.create_checkout_session(checkout_payload, current_user=buyer)

    assert exc_info.value.status_code == 503
    stripe_create.assert_not_called()


@pytest.mark.asyncio
async def test_checkout_does_not_expose_stripe_error_details(
    billing_settings, checkout_payload, buyer
):
    with (
        patch.object(billing, "get_settings", return_value=billing_settings),
        patch.object(
            billing.stripe.checkout.Session,
            "create",
            side_effect=RuntimeError("private Stripe account diagnostics"),
        ),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await billing.create_checkout_session(checkout_payload, current_user=buyer)

    assert exc_info.value.status_code == 502
    assert "private Stripe account diagnostics" not in exc_info.value.detail


def _database_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine, Session(engine)


def _webhook_request(body=b"stripe-event", signature="valid-signature"):
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/billing/webhook",
            "headers": [(b"stripe-signature", signature.encode())],
        },
        receive=receive,
    )


def test_stripe_webhook_is_exempt_from_bearer_auth_for_signature_authentication():
    request = _webhook_request()
    # Stripe cannot provide an AihaX bearer token; the route independently
    # requires Stripe's signed webhook header before applying any event.
    require_auth(request)


@pytest.mark.asyncio
async def test_simulated_checkout_is_disabled_by_default(billing_settings, buyer):
    engine, db = _database_session()
    try:
        db.add(buyer)
        db.commit()
        with patch.object(billing, "get_settings", return_value=billing_settings):
            with pytest.raises(HTTPException) as exc_info:
                await billing.simulate_checkout(
                    SubscriptionCreate(
                        email="other@example.test", plan_name="Pro", duration_days=30
                    ),
                    current_user=buyer,
                    db=db,
                )
        assert exc_info.value.status_code == 403
        assert db.query(Subscription).count() == 0
    finally:
        db.close()
        engine.dispose()


@pytest.mark.asyncio
async def test_enabled_local_simulation_stays_bound_to_authenticated_user(billing_settings, buyer):
    engine, db = _database_session()
    try:
        db.add(buyer)
        db.commit()
        billing_settings.dev_mock_billing = True
        with (
            patch.object(billing, "get_settings", return_value=billing_settings),
            patch.object(billing, "send_smtp_email"),
        ):
            subscription = await billing.simulate_checkout(
                SubscriptionCreate(email="other@example.test", plan_name="Pro", duration_days=30),
                current_user=buyer,
                db=db,
            )
        assert subscription.email == buyer.email
        assert db.query(Subscription).filter_by(email="other@example.test").count() == 0
        assert subscription.plan_name == "Pro"
    finally:
        db.close()
        engine.dispose()


@pytest.mark.asyncio
async def test_verified_checkout_webhook_creates_entitlement_once(billing_settings, buyer):
    engine, db = _database_session()
    try:
        db.add(buyer)
        db.commit()
        event = {
            "id": "evt_checkout_1",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_1",
                    "mode": "subscription",
                    "payment_status": "paid",
                    "subscription": "sub_test_1",
                    "customer": "cus_test_1",
                    "client_reference_id": buyer.id,
                    "metadata": {
                        "user_id": buyer.id,
                        "price_id": "price_pro_monthly",
                        "plan_name": "Pro",
                    },
                }
            },
        }
        with (
            patch.object(billing, "get_settings", return_value=billing_settings),
            patch.object(billing.stripe.Webhook, "construct_event", return_value=event),
            patch.object(
                billing.stripe.Subscription,
                "retrieve",
                return_value={"status": "active", "current_period_end": 2_000_000_000},
            ) as stripe_retrieve,
        ):
            result = await billing.stripe_webhook(_webhook_request(), db)
            duplicate = await billing.stripe_webhook(_webhook_request(), db)

        subscription = db.query(Subscription).one()
        assert result == {"received": True, "duplicate": False}
        assert duplicate == {"received": True, "duplicate": True}
        assert subscription.email == buyer.email
        assert subscription.plan_name == "Pro"
        assert subscription.status == "active"
        assert subscription.stripe_subscription_id == "sub_test_1"
        assert db.query(StripeWebhookEvent).count() == 1
        stripe_retrieve.assert_called_once_with("sub_test_1")
    finally:
        db.close()
        engine.dispose()


@pytest.mark.asyncio
async def test_subscription_invoice_failure_recovery_and_cancellation(billing_settings, buyer):
    engine, db = _database_session()
    try:
        db.add(buyer)
        db.add(
            Subscription(
                email=buyer.email,
                plan_name="Pro",
                status="active",
                end_date=datetime.now(timezone.utc) + timedelta(days=30),
                stripe_subscription_id="sub_lifecycle_1",
            )
        )
        db.commit()

        events = [
            {
                "id": "evt_invoice_failed",
                "type": "invoice.payment_failed",
                "data": {"object": {"subscription": "sub_lifecycle_1"}},
            },
            {
                "id": "evt_invoice_paid",
                "type": "invoice.paid",
                "data": {"object": {"subscription": "sub_lifecycle_1"}},
            },
            {
                "id": "evt_subscription_deleted",
                "type": "customer.subscription.deleted",
                "data": {
                    "object": {
                        "id": "sub_lifecycle_1",
                        "status": "canceled",
                        "current_period_end": 2_000_000_000,
                    }
                },
            },
        ]
        with (
            patch.object(billing, "get_settings", return_value=billing_settings),
            patch.object(billing.stripe.Webhook, "construct_event", side_effect=events),
            patch.object(
                billing.stripe.Subscription,
                "retrieve",
                return_value={"status": "active", "current_period_end": 2_100_000_000},
            ),
        ):
            await billing.stripe_webhook(_webhook_request(), db)
            assert db.query(Subscription).one().status == "past_due"
            await billing.stripe_webhook(_webhook_request(), db)
            assert db.query(Subscription).one().status == "active"
            await billing.stripe_webhook(_webhook_request(), db)
            subscription = db.query(Subscription).one()

        assert subscription.status == "canceled"
        assert db.query(StripeWebhookEvent).count() == 3
    finally:
        db.close()
        engine.dispose()


@pytest.mark.asyncio
async def test_webhook_rejects_invalid_signature_without_database_mutation(
    billing_settings,
):
    engine, db = _database_session()
    try:
        payload = json.dumps(
            {"id": "evt_invalid_signature", "type": "unknown", "data": {"object": {}}}
        ).encode()
        timestamp = int(time.time())
        with patch.object(billing, "get_settings", return_value=billing_settings):
            with pytest.raises(HTTPException) as exc_info:
                await billing.stripe_webhook(
                    _webhook_request(payload, f"t={timestamp},v1=not-a-valid-signature"), db
                )

        assert exc_info.value.status_code == 400
        assert db.query(Subscription).count() == 0
        assert db.query(StripeWebhookEvent).count() == 0
    finally:
        db.close()
        engine.dispose()


@pytest.mark.asyncio
async def test_stripe_sdk_accepts_a_locally_generated_valid_signature(billing_settings):
    engine, db = _database_session()
    try:
        payload = json.dumps(
            {
                "id": "evt_valid_signature",
                "type": "unknown.test.event",
                "data": {"object": {}},
            },
            separators=(",", ":"),
        ).encode()
        timestamp = int(time.time())
        signed_payload = str(timestamp).encode() + b"." + payload
        digest = hmac.new(
            billing_settings.stripe_webhook_secret.encode(), signed_payload, hashlib.sha256
        ).hexdigest()
        signature = f"t={timestamp},v1={digest}"

        with patch.object(billing, "get_settings", return_value=billing_settings):
            result = await billing.stripe_webhook(_webhook_request(payload, signature), db)

        assert result == {"received": True, "duplicate": False}
        assert db.query(StripeWebhookEvent).filter_by(event_id="evt_valid_signature").count() == 1
    finally:
        db.close()
        engine.dispose()


def test_stripe_subscription_migration_upgrades_existing_database():
    engine = create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE schema_migrations "
                    "(version INTEGER PRIMARY KEY, name TEXT NOT NULL, "
                    "checksum TEXT NOT NULL, applied_at DATETIME NOT NULL)"
                )
            )
            connection.execute(
                text(
                    "CREATE TABLE subscriptions "
                    "(id VARCHAR PRIMARY KEY, email VARCHAR NOT NULL, "
                    "plan_name VARCHAR NOT NULL, status VARCHAR NOT NULL, "
                    "start_date VARCHAR NOT NULL, end_date VARCHAR NOT NULL, "
                    "last_notified VARCHAR, created_at VARCHAR NOT NULL)"
                )
            )
            connection.execute(text("CREATE TABLE campaigns (id VARCHAR PRIMARY KEY)"))
            for migration in MIGRATIONS:
                if migration["version"] == 30:
                    break
                connection.execute(
                    text(
                        "INSERT INTO schema_migrations "
                        "(version, name, checksum, applied_at) "
                        "VALUES (:version, :name, :checksum, '2026-01-01')"
                    ),
                    {
                        "version": migration["version"],
                        "name": migration["name"],
                        "checksum": _compute_checksum(migration["up_sql"]),
                    },
                )

        run_migrations(engine)
        with engine.connect() as connection:
            columns = {
                row[1] for row in connection.execute(text("PRAGMA table_info('subscriptions')"))
            }
            event_table = connection.execute(
                text(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name='stripe_webhook_events'"
                )
            ).scalar_one_or_none()
            organization_table = connection.execute(
                text(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name='organizations'"
                )
            ).scalar_one_or_none()
            campaign_columns = {
                row[1] for row in connection.execute(text("PRAGMA table_info('campaigns')"))
            }
            applied_version = connection.execute(
                text("SELECT MAX(version) FROM schema_migrations")
            ).scalar_one()

        assert {
            "stripe_subscription_id",
            "stripe_customer_id",
            "stripe_checkout_session_id",
        } <= columns
        assert event_table == "stripe_webhook_events"
        assert applied_version == 31
        assert organization_table == "organizations"
        assert "organization_id" in campaign_columns
    finally:
        engine.dispose()


def test_expired_subscription_cannot_mint_paid_entitlement(buyer):
    engine, db = _database_session()
    try:
        db.add(buyer)
        db.add(
            Subscription(
                email=buyer.email,
                plan_name="Pro",
                status="active",
                end_date=datetime.now(timezone.utc) - timedelta(days=1),
            )
        )
        db.commit()

        token = EntitlementManager.generate_entitlement_token(db, buyer)
        payload = EntitlementManager.verify_entitlement_token(token)

        assert payload["tier"] == "free"
    finally:
        db.close()
        engine.dispose()


def test_entitlement_is_ed25519_signed_and_bound_to_account(buyer):
    engine, db = _database_session()
    try:
        db.add(buyer)
        db.commit()
        token = EntitlementManager.generate_entitlement_token(db, buyer)
        header = jwt.get_unverified_header(token)

        assert header["alg"] == "EdDSA"
        with pytest.raises(HTTPException) as exc_info:
            EntitlementManager.verify_entitlement_token(token, expected_user_id="another-user")
        assert exc_info.value.status_code == 403

        parts = token.split(".")
        parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
        with pytest.raises(HTTPException) as exc_info:
            EntitlementManager.verify_entitlement_token(".".join(parts))
        assert exc_info.value.status_code == 403
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize(
    ("plan_name", "expected_tier"),
    [
        ("Pro", "pro"),
        ("Pro One-time", "pro"),
        ("Team", "team"),
        ("Agency", "team"),
        ("Enterprise", "team"),
    ],
)
def test_configured_paid_plans_map_to_supported_entitlement_tiers(buyer, plan_name, expected_tier):
    engine, db = _database_session()
    try:
        db.add(buyer)
        db.add(
            Subscription(
                email=buyer.email,
                plan_name=plan_name,
                status="active",
                end_date=datetime.now(timezone.utc) + timedelta(days=30),
            )
        )
        db.commit()

        token = EntitlementManager.generate_entitlement_token(db, buyer)
        payload = EntitlementManager.verify_entitlement_token(token)

        assert payload["tier"] == expected_tier
    finally:
        db.close()
        engine.dispose()
