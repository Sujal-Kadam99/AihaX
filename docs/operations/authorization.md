# AihaX Phase 8 — Mandatory Authorization Model

## 1. Safety Invariant: Fail-Closed Authorization
A campaign cannot transition to `RUNNING` or execute any check tasks without an active, non-expired, and scope-matching `AuthorizationRecord`.

## 2. Authorization Record Schema
* `authorization_id`: Unique identifier
* `campaign_id`: Associated campaign
* `authorized_by`: Name/ID of the authorized operator or customer
* `authorization_type`: `explicit_scope_consent`, `bug_bounty_program`, `written_contract`
* `authorization_reference`: Contract ID, ticket number, or policy link
* `authorized_at`: Creation timestamp
* `expires_at`: Expiration datetime (default: 30 days)
* `scope_hash`: SHA-256 hash over canonical in-scope assets
* `status`: `ACTIVE`, `EXPIRED`, `REVOKED`

## 3. Post-Authorization Scope Mutation Protection
If an operator adds or modifies assets after authorization has been granted, the newly computed scope hash will differ from `auth.scope_hash`, immediately raising a `ScopeMismatchException` and blocking execution.
