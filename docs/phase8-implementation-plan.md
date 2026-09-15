# AihaX — Phase 8 Implementation Plan
## Production Campaign Operations, Persistent State & Evidence Vault

**Status:** APPROVED FOR IMPLEMENTATION  
**Author:** AihaX Engineering Team  
**Date:** 2026-08-28  
**Baseline:** 485 / 485 Passing Backend Tests (Zero Regressions)

---

## 1. Executive Summary & Goals

Phase 8 elevates AihaX from a verified, in-memory 77-check execution and reporting pipeline (Phases 1–7) into a **persistent, resumable, auditable, and production-grade campaign operations platform**.

### Core Guarantees & Non-Negotiable Invariants
1. **Default-Deny Scope & Zero Out-of-Scope Bytes:** Scope validation occurs before any socket or HTTP transmission; redirect destinations are strictly re-validated.
2. **Authorized Targets Only:** A campaign cannot transition to `RUNNING` or execute any network task without a valid, unexpired, scope-matching `AuthorizationRecord`.
3. **No Uncontrolled Exploitation:** Non-destructive testing only. No arbitrary OS execution, reverse shells, denial-of-service, or brute force.
4. **Bounded Concurrency & Persistent Request Budgets:** Multi-worker safe budgets (campaign, target, check, task) that survive process restarts.
5. **Authoritative Evidence & Secret Redaction:** Evidence is immutable, cryptographically anchored with SHA-256 hashes, and stripped of JWTs, passwords, cookies, API keys, and authorization headers before storage.
6. **Crash-Resilient Resumability:** Atomic task claiming via time-bounded leases and automated stale-worker lease recovery.
7. **Cryptographic Manifest & Tamper Detection:** Campaign manifest anchors all scope, config, execution graph, evidence, and report hashes.
8. **Fail Closed:** Any integrity, authorization, budget, or scope failure immediately halts execution.

---

## 2. Current Architecture & Reusable Components

AihaX already provides robust, production-tested components across Phases 1–7:

* **Scope Enforcement:** `backend/core/scope_validator.py` (`ScopeValidator`, domain/URL canonicalization, redirect gating).
* **Network & Rate Limiting:** `backend/services/request_engine.py` (`RequestEngine`, `AuthenticationContext`, `RequestSpec`, `RequestEvidence`).
* **Check Registry (77 Checks):** `backend/core/check_registry.py` (`CheckRegistry`, `CheckContract`, `BaseCheck`, 77 registered checks C001–C077).
* **Deterministic Verification Engine:** `backend/services/verification_engine.py` (`VerificationEngine`, 77 check verification strategies).
* **Finding Deduplication & Lifecycle:** `backend/services/finding_deduplicator.py` (`FindingDeduplicator`, `EvidenceHasher`, `FindingLifecycleState`).
* **Intelligence Layer:** `backend/intelligence/` (`FindingClassifier`, `SeverityEngine`, `ConfidenceEngine`, `EvidenceCorrelator`, `FindingClusterer`, `ReproducibilityEngine`, `RemediationEngine`, `CampaignIntelligenceEngine`, `ReportGuard`).
* **Reporting V2:** `backend/services/bug_bounty_generator_v2.py` (`BugBountyReportGeneratorV2`, fail-closed guard checks).
* **Database & Migrations:** `backend/models/database.py` (SQLAlchemy, SQLite WAL mode, busy timeout 5000ms, foreign keys ON), `backend/models/migrations.py` (transactional checksummed migrations up to version 15).

---

## 3. Gaps & Proposed Changes for Phase 8

| Component | Current State (Phase 7) | Target State (Phase 8) |
|---|---|---|
| **Campaign State** | In-memory `CampaignResult` | Database ORM models (`Campaign`, `CampaignTarget`, `ExecutionTask`, `AuthorizationRecord`, `EvidenceRecord`, `AuditTrailEvent`, `CampaignSnapshot`) |
| **Lifecycle** | Transient execution flow | Deterministic state machine (`DRAFT -> AUTHORIZED -> QUEUED -> RUNNING -> PAUSED -> COMPLETED / FAILED / CANCELLED`) |
| **Execution Queue** | In-memory loop | Persistent, lease-backed, atomically claimed task queue with stale lease recovery |
| **Request Budget** | In-memory `CampaignRequestBudget` | Persistent budget counter with thread-safe / transaction-safe reservation |
| **Evidence Storage** | In-memory `EvidenceChain` / JSON strings | Dedicated `backend/evidence/` Evidence Vault with SHA-256 content addressing, secret redaction, and chain integrity |
| **Campaign Manifest** | Ad-hoc coverage report | Cryptographically verifiable manifest anchoring scope, graph, evidence, findings, and reports |
| **Registry Versioning** | Static registry instance | Versioned snapshot hash & contract hash stored per campaign |
| **Operations Service** | Monolithic `CampaignExecutor` | Decoupled `CampaignOperationsService` for lifecycle/coordination and worker execution |
| **Operator API** | Basic scan endpoints | REST endpoints for campaign lifecycle, status, audit, evidence, and report exports |
| **Observability** | Basic logs | Structured, low-cardinality operational metrics collector |

---

## 4. Package Architecture & New Modules

```text
backend/
├── persistence/
│   ├── __init__.py
│   ├── models.py             # ORM models for Campaign, Target, Task, Auth, Audit, Snapshot
│   ├── repository.py         # Transactional CRUD & atomic lease acquisition
│   └── migrations.py         # Version 16 migration script for Phase 8 tables
├── evidence/
│   ├── __init__.py
│   ├── evidence_store.py     # Content-addressed immutable evidence repository
│   ├── evidence_manifest.py  # Campaign manifest generation & verification
│   ├── integrity.py          # Cryptographic SHA-256 chain and checksum verifiers
│   ├── redaction.py          # Production secret redaction engine (9+ patterns)
│   └── retrieval.py          # Paginated, secret-free evidence query interface
├── services/
│   ├── campaign_operations.py # Lifecycle operations: authorize, queue, start, pause, resume, cancel, recover
│   ├── persistent_budget.py   # Multi-worker persistent request budget tracking
│   └── metrics_collector.py   # Bounded operational metrics collector
├── routers/
│   └── campaigns.py          # Operator-facing REST API routes (/api/campaigns)
```

---

## 5. Database Schema & Migration Strategy (Migration 16)

We append **Migration 16: `016_phase8_persistent_campaign_vault`** to `backend/models/migrations.py` without modifying prior migrations:

1. `campaigns`:
   - `id` VARCHAR PK, `name` VARCHAR, `target_url` VARCHAR, `mode` VARCHAR, `status` VARCHAR (indexed).
   - `program_id` VARCHAR, `user_id` VARCHAR.
   - `created_at`, `started_at`, `completed_at`, `paused_at`.
   - `scope_snapshot_hash`, `config_hash`, `registry_hash`, `manifest_hash`.
   - `campaign_budget` INT, `target_budget` INT, `check_budget` INT, `requests_used` INT, `max_concurrency` INT.
2. `campaign_targets`:
   - `id` VARCHAR PK, `campaign_id` VARCHAR (FK), `normalized_url` VARCHAR, `scope_status` VARCHAR, `auth_status` VARCHAR, `status` VARCHAR.
   - `requests_used` INT.
3. `campaign_tasks`:
   - `id` VARCHAR PK, `campaign_id` VARCHAR (FK), `target_url` VARCHAR, `check_id` VARCHAR, `endpoint_url` VARCHAR, `parameter_name` VARCHAR.
   - `status` VARCHAR (indexed: PENDING, CLAIMED, RUNNING, COMPLETED, RETRY_PENDING, FAILED, CANCELLED).
   - `attempt_count` INT, `max_retries` INT, `budget_reservation` INT.
   - `worker_id` VARCHAR, `lease_expires_at` DATETIME (indexed).
   - `idempotency_key` VARCHAR UNIQUE.
   - `failure_reason` TEXT.
4. `authorization_records`:
   - `id` VARCHAR PK, `campaign_id` VARCHAR (FK), `authorized_by` VARCHAR, `authorization_type` VARCHAR, `authorization_reference` TEXT.
   - `authorized_at` DATETIME, `expires_at` DATETIME, `scope_hash` VARCHAR, `status` VARCHAR.
5. `evidence_records`:
   - `id` VARCHAR PK, `campaign_id` VARCHAR (FK), `finding_id` VARCHAR, `task_id` VARCHAR, `request_id` VARCHAR.
   - `evidence_type` VARCHAR, `target_url` VARCHAR, `method` VARCHAR.
   - `sanitized_request` TEXT, `sanitized_response` TEXT, `payload_summary` TEXT.
   - `content_hash` VARCHAR NOT NULL, `chain_hash` VARCHAR, `created_at` DATETIME.
6. `audit_trail_events`:
   - `id` VARCHAR PK, `campaign_id` VARCHAR (FK), `timestamp` DATETIME, `actor` VARCHAR, `event_type` VARCHAR (indexed).
   - `object_id` VARCHAR, `metadata_json` TEXT.
   - `previous_event_hash` VARCHAR, `event_hash` VARCHAR NOT NULL.

---

## 6. Implementation Sequence

```text
Step 1:  Audit & Implementation Plan (Completed)
Step 2:  Persistence Layer (models, repository, migrations.py v16)
Step 3:  Campaign State Machine & Authorization Enforcement
Step 4:  Resumable Task Queue & Atomic Worker Leases
Step 5:  Persistent Multi-Worker Request Budget
Step 6:  Evidence Vault & Secret Redaction Engine
Step 7:  Campaign Manifest & Cryptographic Integrity Verifier
Step 8:  Campaign Operations Service
Step 9:  Integration with CampaignExecutor & Finding Engine
Step 10: Operator REST API Routes (/api/campaigns)
Step 11: Structured Observability & Metrics Collector
Step 12: Security Lab Failure Scenarios
Step 13: Phase 8 Test Suite (Persistence, Evidence, Operations, E2E, Invariants)
Step 14: Targeted Subsystem Validation
Step 15: Full Regression Suite (Verify all 485 + Phase 8 tests pass)
Step 16: Static Security & Invariant Verification
Step 17: Final Phase 8 Walkthrough Documentation
```

---

## 7. Testing & Quality Assurance Plan

* **Persistence Unit Tests (`backend/tests/persistence/`):**
  - `test_campaign_persistence.py`: CRUD, reload integrity, status transitions.
  - `test_task_leases.py`: Atomic claiming, lease expiration, stale worker recovery.
  - `test_idempotency.py`: Re-executing tasks, findings, and reports produces stable single records.
  - `test_transactions.py`: SQLite transaction safety and rollbacks.
  - `test_snapshots.py`: Immutable configuration snapshot verification.

* **Evidence Vault Tests (`backend/tests/evidence/`):**
  - `test_evidence_store.py`: Immutable write, content-addressed storage.
  - `test_evidence_integrity.py`: SHA-256 chain verification, tamper detection.
  - `test_redaction.py`: Redaction of JWTs, API keys, cookies, passwords, bearer tokens.
  - `test_manifest.py`: Campaign manifest generation and tamper detection.

* **Operations Tests (`backend/tests/operations/`):**
  - `test_campaign_state_machine.py`: Strict lifecycle transitions, invalid transition rejections.
  - `test_authorization.py`: Mandatory auth gating, expired auth rejection, scope mismatch rejection.
  - `test_pause_resume.py`: Pause halts new tasks, resume continues pending tasks.
  - `test_cancel.py`: Cooperative cancellation.
  - `test_recovery.py`: Process crash simulation and resumption.

* **End-to-End & Security Invariants:**
  - `backend/tests/test_phase8_e2e.py`: Full campaign operations lifecycle e2e.
  - `backend/tests/test_phase8_security_invariants.py`: Static network isolation, secret leakage scan, destructive payload scan.

---

## 8. Rollback & Safety Strategy

1. **Zero Destructive Changes:** Migration 16 adds new tables and columns; no existing tables are dropped or modified destructively.
2. **Backward Compatibility:** Existing `CampaignExecutor` and scan endpoints remain intact and functional.
3. **Fail-Closed Default:** If any Phase 8 persistent feature encounters an unrecoverable database or authorization error, operations halt safely without generating unverified traffic.
