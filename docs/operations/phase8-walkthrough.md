# AihaX Phase 8 Walkthrough — Production Campaign Operations, Persistent State & Evidence Vault

## 1. Phase 8 Objective
Transition AihaX from an in-memory execution pipeline into an enterprise-grade, persistent, resumable, auditable, and production-ready security campaign operations platform while strictly maintaining all safety invariants established in Phases 1–7.

---

## 2. Architecture Overview

```text
                    ┌────────────────────┐
                    │ Campaign Definition│
                    └─────────┬──────────┘
                              ↓
                    ┌────────────────────┐
                    │ Scope Validation + │
                    │ Auth Record Check  │
                    └─────────┬──────────┘
                              ↓
                    ┌────────────────────┐
                    │ Persistent State   │
                    │ (SQLite WAL)       │
                    └─────────┬──────────┘
                              ↓
             ┌────────────────┴────────────────┐
             ↓                                 ↓
      Recon / Planning                  Execution Queue
             ↓                                 ↓
      Execution Graph                  Atomic Leases (60s)
             └────────────────┬────────────────┘
                              ↓
                        RequestEngine
                              ↓
                        Evidence Vault
                     (SHA-256 Chained)
                              ↓
                      VerificationEngine
                              ↓
                     Finding Intelligence
                              ↓
                      CoverageValidator
                              ↓
                    BugBountyGenerator V2
                              ↓
                     Campaign Manifest &
                   Tamper-Evident Audit Trail
```

---

## 3. Actual Implementation
* **Persistence Layer (`backend/persistence/`):** ORM entities for campaigns, targets, execution tasks, authorization records, evidence vault entries, audit trail events, and immutable snapshots.
* **Database & Migration (`backend/models/migrations.py`):** SQLite with WAL mode, busy timeout 5000ms, and Migration 16 (`016_phase8_persistent_campaign_vault`) with SHA-256 migration checksum validation.
* **Campaign Operations Service (`backend/services/campaign_operations.py`):** Coordinates lifecycle transitions, task claims, budget allocations, manifest generation, and integrity checks.
* **Evidence Vault (`backend/evidence/`):** Pre-persistence secret redaction (9+ patterns), deterministic content hashing, sequential hash chaining, and Merkle-style root manifest generation.
* **REST API Router (`backend/routers/campaigns.py`):** Full endpoint suite for campaign CRUD, authorization, start, pause, resume, cancel, status, findings, coverage, reports, evidence, audit, integrity, and operational metrics.

---

## 4. Campaign Lifecycle & State Machine
The state machine strictly governs campaign state transitions:

```text
       ┌──────────┐
       │  DRAFT   ├────────────────────────┐
       └────┬─────┘                        │
            │ (authorize)                  │
            ▼                              │
       ┌──────────┐                        │
       │AUTHORIZED├───────────┐            │
       └────┬─────┘           │            │
            │ (queue)         │ (start)    │ (cancel)
            ▼                 │            │
       ┌──────────┐           │            │
       │  QUEUED  │           │            │
       └────┬─────┘           │            │
            │ (start)         │            │
            ▼                 ▼            │
       ┌────────────────────────┐          │
       │        RUNNING         │          │
       └───┬─────────────┬──────┘          │
           │ (pause)     │ (complete)      │
           ▼             ▼                 │
     ┌──────────┐  ┌───────────┐           │
     │  PAUSED  │  │ COMPLETED │ (terminal)│
     └───┬──────┘  └───────────┘           │
         │ (resume)                        │
         └────────► [RUNNING]              │
                                           ▼
                                    ┌───────────┐
                                    │ CANCELLED │ (terminal)
                                    └───────────┘
```

Terminal states (`COMPLETED`, `CANCELLED`, `FAILED`) cannot be resumed or restarted.

---

## 5. Authorization Boundary
* No campaign can transition to `RUNNING` without a valid `AuthorizationRecord`.
* The authorization record contains authorized party, authorization type, ticket reference, duration, expiration timestamp, and `scope_hash = SHA256(sorted_in_scope_urls)`.
* If targets are added or mutated post-authorization, `ScopeMismatchException` fails closed and halts execution.
* Expired authorizations are rejected immediately.

---

## 6. Scope Boundary
* **Default-Deny:** Target URLs must be explicitly validated by `ScopeValidator`.
* **Zero Out-of-Scope Bytes:** Scope validation occurs prior to socket or HTTP transport.
* **Redirect Protection:** All HTTP redirects are checked against the scope validator before following.

---

## 7. Persistent Execution
* Every check against an asset endpoint is modeled as an `ExecutionTask` in the `campaign_tasks` table.
* Tasks have idempotency keys `SHA256(campaign_id|check_id|endpoint_url|param)`. Duplicate check submissions resolve to the existing task record.

---

## 8. Worker Leases
* Concurrency is managed via time-bounded leases (`lease_expires_at`).
* `claim_tasks()` atomically claims available `PENDING` / `RETRY_PENDING` tasks for a specific `worker_id`.
* Other workers cannot claim tasks under an active unexpired lease.
* Workers renew leases via `renew_task_lease()` and mark completion via `complete_task()`.

---

## 9. Crash Recovery
* If a worker process crashes, its task lease expires.
* `CampaignOperationsService.recover_stale_tasks()` scans for expired leases:
  - If `attempt_count < max_retries`, task status is reset to `RETRY_PENDING` and unassigned.
  - If `attempt_count >= max_retries`, task is transitioned to `FAILED`.
* Resumed campaigns or surviving workers claim recovered tasks seamlessly.

---

## 10. Persistent Request Budgets
* `PersistentRequestBudget` enforces 3 hierarchical limits:
  1. Campaign Budget (e.g. 500 requests)
  2. Target Budget (e.g. 100 requests)
  3. Check Budget (e.g. 20 requests)
* Atomic reservation tokens prevent race conditions across concurrent workers. Limits survive process restarts.

---

## 11. Candidate Finding Lifecycle
AihaX strictly enforces the distinction: **Candidate Finding ≠ Confirmed Vulnerability**.

When a check observes anomalous response behavior (e.g., status differences, reflected characters, header changes), it generates a `Finding` in `CANDIDATE` state.

```text
Check Execution
     ↓
Observed Anomaly
     ↓
Candidate Finding (Status: CANDIDATE, Confidence: Unscored)
     ↓
Safe Verification Engine
     ↓
┌───────────────────────┐
│                       │
VERIFIED            UNVERIFIED / FALSE POSITIVE
│                       │
↓                       ↓
Confirmed Finding   Candidate Retained / Rejected
│
↓
Bug Bounty Report
```

---

## 12. Safe Verification Lifecycle
* `VerificationEngine` receives the `Candidate Finding`.
* Verification runs non-destructive, bounded, and deterministic checks (e.g. math canaries `31337`, differential parameter testing, header comparison).
* Every verification request MUST route through `RequestEngine` (enforcing Scope, rate limits, timeouts, and redaction).
* If safe verification is not possible or inconclusive, the finding remains `UNVERIFIED` / `INCONCLUSIVE` and is NEVER reported as a confirmed vulnerability.
* The system **never manufactures certainty** and **never exploits destructively**.

---

## 13. Evidence Vault & Secret Redaction
* Secrets are redacted **prior to persistence** via `backend/evidence/redaction.py`.
* Patterns redacted:
  - JWT tokens (`eyJ...`) -> `[REDACTED-JWT]`
  - Authorization headers -> `Authorization: Bearer [REDACTED]`
  - Passwords and secret parameters -> `[REDACTED]`
  - Session cookies -> `Cookie: [REDACTED]`
  - AWS access keys -> `[REDACTED-AWS-KEY]`
  - Private RSA / EC keys -> `[REDACTED-PRIVATE-KEY]`

---

## 14. Cryptographic Integrity
* Every evidence record is content-addressed:
  `content_hash = SHA256(canonical_json(evidence_type, target, method, sanitized_req, sanitized_resp, summary))`
* Sequential evidence entries are chained:
  `chain_hash = SHA256(content_hash | previous_chain_hash | timestamp)`
* Audit trail events are chained:
  `event_hash = SHA256(campaign_id | event_type | actor | timestamp | metadata | previous_hash)`

---

## 15. Campaign Root Manifest
* `ManifestBuilder` constructs a Merkle-style root manifest containing:
  - Scope hash
  - Config snapshot hash
  - Execution graph hash
  - Sorted evidence hashes
  - Finding hashes
  - Report hashes
* `GET /api/campaigns/{id}/integrity` verifies authorization validity, snapshot integrity, evidence vault content and chain hashes, and audit trail chaining.

---

## 16. Operator REST API Lifecycle
* `POST /api/campaigns`: Create campaign in `DRAFT`
* `GET /api/campaigns`: List campaigns with pagination
* `GET /api/campaigns/{id}`: Detailed status
* `POST /api/campaigns/{id}/authorize`: Record cryptographic authorization
* `POST /api/campaigns/{id}/start`: Begin execution
* `POST /api/campaigns/{id}/pause`: Safely pause execution
* `POST /api/campaigns/{id}/resume`: Resume execution
* `POST /api/campaigns/{id}/cancel`: Abort execution to terminal state
* `GET /api/campaigns/{id}/status`: Task counts and budget usage
* `GET /api/campaigns/{id}/findings`: Paginated findings (supports status/severity filters)
* `GET /api/campaigns/{id}/coverage`: Target and check coverage summary
* `GET /api/campaigns/{id}/evidence`: Secret-free evidence retrieval
* `GET /api/campaigns/{id}/audit`: Chained audit trail
* `GET /api/campaigns/{id}/integrity`: Live cryptographic verification
* `POST /api/campaigns/{id}/reports`: Bug bounty report generation (verified findings only)
* `GET /api/campaigns/metrics/operational`: Low-cardinality observability metrics

---

## 17. Pause / Resume / Cancel Semantics
* **Pause:** Running tasks finish their bounded execution, but workers are blocked from claiming new tasks. Campaign state is preserved in DB.
* **Resume:** Resumes task claims after verifying that authorization is still active and unexpired.
* **Cancel:** Transitions campaign to `CANCELLED` and marks pending/claimed tasks `CANCELLED`. Terminal state.

---

## 18. Test Results

```text
============================== test session starts ==============================
TOTAL TESTS:   530
PASSED:        530
FAILED:          0
ERRORS:          0
REGRESSIONS:     0
EXECUTION TIME: 110.15s
================================================================================
```

### Complete Test Distribution
* **Baseline Tests (Phases 1–7):** 485 tests
* **Persistence & Task Lease Tests:** 17 tests
* **Evidence Vault & Redaction Tests:** 14 tests
* **Operations & State Machine Tests:** 9 tests
* **E2E Integration Test:** 1 test
* **Security Invariants Tests:** 4 tests

---

## 19. Static Security Verification
* **Zero Raw Network Imports in Checks:** No `import socket`, `import requests`, or `import urllib` in `backend/agents/checks/`.
* **Non-Destructive Checks:** 77/77 checks confirmed non-destructive (`destructive=False`).
* **Zero Destructive Patterns:** No `DROP TABLE`, `rm -rf`, or reverse shells in check logic.
* **Secret Redaction Verification:** 100% of simulated secret headers/tokens redacted.

---

## 20. Known Limitations
* Multi-node distributed clusters will require Redis or PostgreSQL advisory locks for horizontal worker scaling beyond single-host SQLite WAL concurrency.
* Browser-dependent checks require local Chromium / Playwright binaries.

---

## 21. Remaining Gaps
* Zero critical safety gaps.
* High/Medium operational enhancements documented in [`docs/phase8-gap-analysis.md`](file:///c:/Users/sujal/OneDrive/Documents/Desktop/Aihax/docs/phase8-gap-analysis.md).

---

## 22. Phase 8 Certification Status
**`PHASE 8 CERTIFIED`**
* All 18 original requirements implemented and verified.
* 530 / 530 tests passing with 0 failures and 0 regressions.
* Candidate Finding -> Safe Verification -> Confirmed Finding pipeline fully verified.
* All safety and cryptographic invariants enforced.
