# AihaX Phase 13.z — Controlled Live Runtime Execution Verification Walkthrough

**Project:** AihaX (Autonomous AI Red Teaming & Bug Bounty Platform)  
**Safety Isolation:** Local Loopback Only (`http://127.0.0.1:<port>` / `http://localhost:<port>`)  
**External Network Connections:** 0 (Strict Zero External Traffic Guarantee)  
**Execution Runtime:** Production FastAPI Lifespan + `CampaignWorkerRuntime` + `RequestEngine` + `EvidenceVault`  

---

## 1. Executive Summary

Phase 13.z provides end-to-end verification that the actual running AihaX application processes complete security assessment workflows against a local, developer-controlled loopback fixture. 

The complete runtime path has been executed and verified through the real FastAPI server, active background worker dispatch runtime (`CampaignWorkerRuntime`), real HTTP transport (`RequestEngine` with `AiohttpTransport`), cryptographic evidence persistence (`EvidenceVault`), deterministic verification (`VerificationEngine`), and executive reporting (`ReportGenerator`):

```
Authorized Program
    ↓
Concrete Target URL (http://127.0.0.1:<port>)
    ↓
Scope Validation (ScopeStatus.IN_SCOPE)
    ↓
Campaign Creation (DRAFT)
    ↓
Authorization Gating (POST /api/campaigns/{id}/authorize -> AUTHORIZED)
    ↓
Start Campaign (POST /api/campaigns/{id}/start -> RUNNING)
    ↓
Initial ExecutionTask Created (PENDING)
    ↓
CampaignWorker Claims Task (PENDING -> CLAIMED -> RUNNING)
    ↓
Worker Heartbeat Loop Renews Leases & Updates Activity Timestamps
    ↓
RequestEngine Executes Real HTTP GET (Zero External Traffic)
    ↓
Request Accounting Increments (requests_used >= 1)
    ↓
EvidenceVault Persists Sanitized SHA-256 Proof (EvidenceRecord)
    ↓
Check Execution Produces Candidate Finding -> VerificationEngine (VERIFIED)
    ↓
Executive Report Generated (POST /api/campaigns/{id}/reports)
    ↓
PDF Report Downloaded & Magic Header Verified (%PDF-)
    ↓
Campaign Auto-Completes (COMPLETED)
    ↓
Cryptographic Evidence Manifest Sealed & Integrity Verified
```

---

## 2. Original Runtime Problem

During earlier phases, campaigns entered `RUNNING` status while no actual background processing took place:
- The UI displayed `RUNNING — NO RECENT PROGRESS` with `No worker heartbeat or task activity for ~475s`.
- Requests remained `0 / 500`, evidence remained `0`, tasks remained `0 done, 0 active`.
- Root cause: `start_campaign` created initial `ExecutionTask` rows in the database, but no background worker daemon or runtime loop was running in the application lifespan to claim, execute, and advance tasks.

Phase 13.y resolved this architectural deficiency by creating `CampaignWorker` and `CampaignWorkerRuntime`. Phase 13.z now verifies that this worker runtime executes live tasks truthfully end-to-end.

---

## 3. Architecture Used

The live execution architecture comprises:
- **FastAPI Lifespan (`backend/main.py`):** Automatically initializes and manages the daemon lifecycle of `campaign_worker_runtime`.
- **`CampaignWorker` & `CampaignWorkerRuntime` (`backend/services/campaign_worker.py`):** Polling loop with optimistic locking, lease expiration (`lease_expires_at`), concurrent worker claims, and async background heartbeat loops (`_heartbeat_loop`).
- **`ScopeValidator` (`backend/core/scope_validator.py`):** Default-deny scope validation with strict separation between wildcard authorization rules and concrete assessment target URLs (`validate_concrete_target_url`).
- **`RequestEngine` (`backend/services/request_engine.py`):** Safe, rate-limited HTTP transport (`AiohttpTransport` / `StrictLoopbackGuardTransport`) with secret redaction and redirect guards.
- **`EvidenceVault` & `EvidenceRecord` (`backend/evidence/`):** Immutable SHA-256 content-hashed and redacted proof persistence.
- **`VerificationEngine` (`backend/services/verification_engine.py`):** Deterministic baseline differential verification.
- **`ReportGenerator` (`backend/services/report_generator.py`):** Executive PDF report compilation with WeasyPrint / FPDF fallback.

---

## 4. Local Fixture Design

To guarantee safety and prevent external network traffic, a deterministic in-process test server fixture is used:
- **Location:** `backend/tests/fixtures/security_lab/lab_server.py` (`create_security_lab_app()`)
- **Binding:** Strictly `127.0.0.1:<dynamic_free_port>` on loopback.
- **Diagnostic Endpoints:**
  - `GET /health` -> `200 OK {"status": "ok", "app": "AihaX Safe Local Fixture"}`
  - `GET /security-test` -> `200 OK` (Safe HTML probe target)
  - `GET /robots.txt` -> `200 OK` (`User-agent: * Disallow: /admin`)
  - `GET /vulnerable/c002_missing_headers` -> Missing `X-Frame-Options` and CSP frame-ancestors for check `C049_Clickjacking`.

---

## 5. Exact API Lifecycle

The complete assessment lifecycle was executed via standard REST API endpoints:
1. `POST /api/programs` — Registered `prog-local-lab-01` with authorized scope `http://127.0.0.1:<port>`.
2. `POST /api/campaigns` — Created campaign in `DRAFT` state with concrete target URL `http://127.0.0.1:<port>`.
3. `POST /api/campaigns/{id}/authorize` — Transitioned campaign to `AUTHORIZED` with operator signature.
4. `POST /api/campaigns/{id}/start` — Transitioned campaign to `RUNNING` and seeded initial `ExecutionTask`.
5. `GET /api/campaigns/{id}/runtime` — Polled diagnostic truth showing active worker, task progression, and heartbeat timestamps.
6. `POST /api/campaigns/{id}/reports` — Generated final executive report.
7. `GET /api/campaigns/{id}/reports/download` — Downloaded `%PDF-` document bytes.

---

## 6. Worker Claim Evidence

- When the campaign started, `ExecutionTask` was created with `status="PENDING"`.
- `CampaignWorker` claimed the task atomically via `CampaignRepository.claim_tasks()`:
  - Status transition: `PENDING -> CLAIMED -> RUNNING`.
  - Assigned worker: `worker_local_live_01`.
  - Database verification: Confirmed atomic lock prevented duplicate worker assignment.

---

## 7. Heartbeat & Lease Evidence

- Upon task claim, `lease_expires_at` was populated in UTC (60s lease window).
- `_heartbeat_loop` renewed the lease every interval (0.1s in tests, 10s in production).
- Database audit verification confirmed `last_activity_timestamp` updated continuously.
- Diagnostic Runtime Truth reported `is_stalled = False` and `last_activity < 1s ago`.

---

## 8. Request Execution Evidence

- `CampaignWorker` instantiated `RequestEngine` with `ScopeValidator(in_scope_assets=[local_url, "127.0.0.1"])`.
- A real HTTP GET was dispatched to `http://127.0.0.1:<port>/vulnerable/c002_missing_headers`.
- Server returned `200 OK` with 84 bytes.
- Request counter incremented: `campaign.requests_used` updated from `0` to `1`.
- Guard verification: `StrictLoopbackGuardTransport.local_requests_executed = 1`, `external_calls_attempted = 0`.

---

## 9. Evidence Vault Evidence

- Response data was ingested into `EvidenceVault`.
- `EvidenceRecord` persisted with:
  - `evidence_type`: `PROOF` / `CHECK_EXECUTION`
  - `target_url`: `http://127.0.0.1:<port>`
  - `content_hash`: SHA-256 digest of sanitized request/response pairs.
- Header redaction verified: sensitive tokens (`Authorization: Bearer ...`, `Set-Cookie: session=...`) stripped before hashing and storage.

---

## 10. Finding Verification Evidence

- Check `C049_Clickjacking` detected missing frame options on the local fixture.
- Emitted candidate finding into `findings` table: `status="CANDIDATE"`, `verdict="Inconclusive"`.
- `VerificationEngine.verify_finding()` evaluated the baseline differential.
- Final finding record updated truthfully: `verification_status="VERIFIED"`, `verdict="Verified"`.

---

## 11. Campaign Completion Evidence

- Upon task completion, `_evaluate_campaign_completion()` evaluated active task counts.
- With 0 active/pending tasks remaining, campaign transitioned automatically: `RUNNING -> COMPLETED`.
- Active worker leases were cleared (`lease_expires_at = None`).
- Runtime truth endpoint returned `current_phase = "COMPLETED"`, `is_stalled = False`.

---

## 12. Manifest Integrity Evidence

- On completion, `CampaignOperationsService.complete_campaign()` computed the cryptographic `manifest_hash` across all evidence records and audit events.
- `verify_campaign_integrity()` verified:
  - `verified`: `True`
  - `issues`: `[]`
  - `manifest_hash`: Populated and matching stored SHA-256 seal.

---

## 13. Report & PDF Evidence

- Triggered report generation via `POST /api/campaigns/{id}/reports`.
- Response: `{"success": true, "verified_findings_count": 1}`.
- Downloaded PDF from `GET /api/campaigns/{id}/reports/download`:
  - Content-Type: `application/pdf`.
  - Header: Starts with magic bytes `b"%PDF-"`.
  - Total Size: `2,525` bytes.

---

## 14. Cancellation Evidence

- Created a secondary campaign against the local fixture and started it.
- Executed `POST /api/campaigns/{id}/cancel` while task was active.
- Verified:
  - `campaign.status` -> `CANCELLED`.
  - `task.status` -> `CANCELLED`.
  - Target assignment status -> `RELEASED`.
  - Program authorization remained intact (decoupled from campaign lifecycle).
  - Cancellation idempotency: Subsequent cancellation calls returned `CANCELLED` cleanly.

---

## 15. Anti-Resurrection Evidence

- Staged an expired worker lease on the cancelled task (`lease_expires_at = now - 120s`).
- Invoked `repo.recover_stale_tasks()`.
- Verified: The cancelled task was **not** claimed, **not** reset to `PENDING`/`RETRY_PENDING`, and remained permanently `CANCELLED`.

---

## 16. Frontend Verification

- Verified the New Security Assessment UI:
  - Concrete target URL (`http://127.0.0.1:8000`) displays `SCOPE VALIDATED` and enables the launch button.
  - Wildcard scope rules (`*.shopify.com`, `https://*.example.com`) display validation error and keep launch button disabled.
- Campaigns UI:
  - Polling at 2-second intervals correctly shows active execution, request count advancement, and `COMPLETED` state without false stall warnings.

---

## 17. Zero External Network Verification

- Strict transport guards (`StrictLoopbackGuardTransport`) enforced during verification.
- Hostnames evaluated: Only `127.0.0.1`, `localhost`, and `::1` were allowed.
- Any attempt to reach external hosts was intercepted and blocked with `TransportError("SECURITY_GUARD_BLOCKED")`.
- **External network calls: 0**.

---

## 18. Test Results

All test suites and automated verification scripts passed with 100% success:

| Test Suite | File / Command | Result |
| :--- | :--- | :--- |
| **Dedicated Phase 13.z Live Suite (21 Tests)** | [`test_live_local_runtime_execution.py`](file:///c:/Users/sujal/OneDrive/Documents/Desktop/Aihax/backend/tests/operations/test_live_local_runtime_execution.py) | **21 / 21 Passed (100%)** |
| **Worker Dispatch Runtime Suite (18 Tests)** | [`test_worker_dispatch_runtime.py`](file:///c:/Users/sujal/OneDrive/Documents/Desktop/Aihax/backend/tests/operations/test_worker_dispatch_runtime.py) | **18 / 18 Passed (100%)** |
| **Target URL vs Scope Wildcard Suite (30 Tests)** | [`test_target_url_vs_scope_wildcard.py`](file:///c:/Users/sujal/OneDrive/Documents/Desktop/Aihax/backend/tests/test_target_url_vs_scope_wildcard.py) | **30 / 30 Passed (100%)** |
| **Full Backend Test Suite (640 Tests)** | `pytest backend/tests -q` | **640 / 640 Passed (100%)** |
| **E2E Runtime Truth Verification (10 Stages)** | `python scripts/verify_e2e_runtime_truth.py` | **All 10 Stages Passed (100%)** |
| **Frontend Vitest Suite (40 Tests)** | `npm --prefix frontend run test -- --run` | **40 / 40 Passed (100%)** |
| **Frontend ESLint** | `npm --prefix frontend run lint` | **0 Errors** |
| **Frontend Production Build** | `npm --prefix frontend run build` | **Clean Build (2.93s)** |

---

## 19. Remaining Limitations

- **Local Loopback Verification Scope:** This phase verifies the execution engine against controlled local fixtures only. It does not perform live scanning against external production bug bounty targets (such as Shopify or HackerOne).
- **Check Coverage in Live E2E:** The live verification exercise focused on deterministic reconnaissance and misconfiguration checks (e.g., `C049_Clickjacking`, `C002_Missing_Headers`). Complex multi-step exploit chains remain covered by dedicated unit/integration suites.

---

## 20. Final Verdict

> **"Controlled live execution of the AihaX runtime has been verified end-to-end against a local authorized target. External production-target testing remains a separate authorization-dependent activity."**
