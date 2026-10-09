# Signed offline entitlements

AihaX uses Ed25519-signed JSON Web Tokens for subscription tiers. The cloud issuer holds `ENTITLEMENT_SIGNING_PRIVATE_KEY`; the desktop verifier receives only `ENTITLEMENT_VERIFICATION_PUBLIC_KEY`. Do not package or copy the private key into a desktop build.

## Key setup

Create a dedicated Ed25519 key pair:

```sh
openssl genpkey -algorithm Ed25519 -out entitlement-private.pem
openssl pkey -in entitlement-private.pem -pubout -out entitlement-public.pem
openssl base64 -A -in entitlement-private.pem
openssl base64 -A -in entitlement-public.pem
```

Set the private key value only in the cloud issuer's secret store. Set the matching public key in cloud and desktop configuration. Configure `ENTITLEMENT_ISSUER` to a stable issuer identifier. A cloud deployment fails configuration validation when either key is absent.

## Issuing and using a cached entitlement

An authenticated account calls `GET /api/billing/entitlements`. The issuer derives the tier from its subscription record, signs claims containing issuer, audience, account ID, tier, issue time, and expiry, then stores the signed token in `entitlement_cache`. The offline grace period is at most seven days and never extends past the paid-through date.

The local feature gate verifies the token using the public key and checks the issuer, audience, expiry, allowed tier, and account ID before granting a tier. Missing, expired, invalid, or cross-account cache entries resolve to the free tier. A desktop installation cannot issue a replacement token because it has no signing private key.

## Operating boundary

This repository contains the signing and verification mechanisms. A production deployment still needs a cloud issuer URL and deployment secret provisioning; local Stripe settings alone do not create a hosted subscription service. Never treat a local database subscription row as proof of a paid tier.
