# AihaX Phase 14 — Production Execution & Authorization Safety Audit

**Repository:** `c:/Users/sujal/OneDrive/Documents/Desktop/Aihax`  
**Phase:** Phase 14 (Production Bug-Bounty Execution Readiness & Authorization-Safe Live Assessment)  
**Date:** 2026-08-29  
**Status:** Audit Complete — Ready for Implementation  

---

## 1. Existing Protections (Baseline Verified)

AihaX possesses a strong security architecture established through Phases 1–13:

1. **Default-Deny Scope Enforcement (`ScopeValidator`):**
   - Precedence: `EXPLICIT_EXCLUSION > EXPLICIT_INCLUSION > WILDCARD_INCLUSION > DEFAULT_DENY`.
   - Wildcards (e.g. `*.example.com`) are strictly treated as authorization rules and can never be used as executable assessment targets.
2. **Concrete Target URL Normalization (`validate_concrete_target_url`):**
   - Rejects wildcards (`*`), credentials/userinfo (`user:pass@`), dangerous schemes (`javascript:`, `file:`, `data:`).
   - Requires explicit `http://` or `https://` prefix and canonicalizes hostname and port.
3. **Central Request Engine (`RequestEngine`):**
   - Gated by `ScopeValidator` prior to any socket or network byte transmission.
   - Independent scope validation on every hop during redirect following.
   - Token bucket rate limiter (`AsyncTokenBucket`) and concurrency semaphore (`asyncio.Semaphore`).
   - Secret redaction for passwords, bearer tokens, API keys, and session cookies (`redact_headers`, `redact_body`).
4. **Campaign Operations & Worker Runtime (`CampaignOperationsService`, `CampaignWorker`):**
   - Finite state machine: `DRAFT -> AUTHORIZED -> QUEUED / RUNNING -> COMPLETED / CANCELLED / PAUSED`.
   - Atomic task claims with leases (`lease_expires_at`) and background heartbeat renewal (`_heartbeat_loop`).
   - Cooperative cancellation and crash-safe recovery without task resurrection.
5. **Evidence Vault & Manifest Sealing (`EvidenceVault`, `ManifestBuilder`):**
   - Immutable SHA-256 content hashes for all evidence records.
   - Sealed `manifest_hash` verifying evidence integrity upon campaign completion.

---

## 2. Identified Gaps & Missing Protections

| Area | Current Behavior | Required Production Hardening |
|---|---|---|
| **Worker Execution Authorization Gate** | `CampaignWorker.execute_task` validates URL syntax and scope, but relies on initial `start_campaign` for auth validation. | Worker must reload authoritative campaign state and verify `AuthorizationRecord.status == "ACTIVE"`, `expires_at > now()`, and `scope_hash` matches current targets before executing each task. |
| **Scope Snapshot Tampering Detection** | `CampaignSnapshot` is saved at creation, but not re-hashed and verified at task execution time. | At task execution time, verify `hashlib.sha256(snapshot_json) == snapshot_hash` and matches `campaign.scope_snapshot_hash`. If tampered, fail closed and emit audit event. |
| **Server-Side Budget Enforcement in Worker** | `campaign.requests_used` is incremented after execution, but pre-check before network execution is needed in `execute_task`. | Fail closed in `CampaignWorker.execute_task` if `campaign.requests_used >= campaign.campaign_budget` or if target budget is exceeded. |
| **SSRF / Cloud Metadata Protection** | `validate_concrete_target_url` checks URL syntax and wildcards; `url_validator.py` has basic IP checks. | Unified destination safety policy: block cloud metadata (`169.254.169.254`, `metadata.google.internal`), link-local (`169.254.0.0/16`, `fe80::/10`), loopback (unless test flag enabled), and private IP spaces unless explicitly in authorized scope. |
| **Pause / Resume Safety** | `pause_campaign` transitions status to `PAUSED`, but `resume_campaign` needs strict re-verification of authorization expiry and snapshot integrity. | `resume_campaign` must fail closed if authorization has expired while paused, or if scope rules were modified. |
| **UI Representation Clarity** | UI shows status but does not clearly display authorization expiration time or pre-flight checklist. | Add Pre-Flight checklist in `NewAssessment.jsx`, show authorization countdown in `Campaigns.jsx`, and decoupled program vs campaign status in `Targets.jsx`. |

---

## 3. Network Path Audit (Potential External Access Analysis)

All files in `backend/` were scanned for direct network client usage:
- `backend/services/request_engine.py`: Uses `aiohttp.ClientSession` strictly inside `AiohttpTransport` behind `ScopeValidator`. (Authoritative execution gate).
- `backend/core/auth.py`: Uses `requests.get` only for Google OIDC tokeninfo verification at `/api/auth/google/login`. (Not target-network testing).
- `backend/services/watch_scheduler.py`: Uses `requests.post` only for sending webhook alert notifications. (Not target-network testing).
- **Finding:** There are **zero** unmonitored target-network HTTP bypasses in the backend codebase. All security check execution passes through `RequestEngine`.

---

## 4. Recommendations & Execution Plan

1. **Step 2 & 3:** Enhance `_verify_authorization_or_raise` in `CampaignOperationsService` and wire it directly into `CampaignWorker.execute_task` to ensure authorization is checked immediately before every task execution and reject expired authorizations.
2. **Step 4:** Implement `verify_scope_snapshot_integrity(campaign_id)` verifying stored `CampaignSnapshot` and cryptographic hash matching `campaign.scope_snapshot_hash`.
3. **Step 5 & 6:** Integrate cloud metadata (`169.254.169.254`) and SSRF protection into `ScopeValidator` and `validate_concrete_target_url`.
4. **Step 7:** Ensure `RequestEngine` redirect validation explicitly blocks redirects to cloud metadata and out-of-scope destinations.
5. **Step 8 & 9:** Enforce request budget checking before task dispatch and execution.
6. **Step 10:** Harden `resume_campaign` to revalidate authorization expiration and scope snapshot.
7. **Step 11 & 12:** Update `NewAssessment.jsx`, `Campaigns.jsx`, and `Targets.jsx` with pre-flight checklist and clear authorization expiration displays.
8. **Step 16 & 17:** Create `scripts/verify_phase14_production_execution.py` and dedicated unit/integration tests in `backend/tests/test_phase14_production_safety.py`.
9. **Step 18 & 19:** Execute full verification and create `docs/phase14_production_execution_walkthrough.md`.
