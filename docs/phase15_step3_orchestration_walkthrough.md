# AihaX Phase 15 Step 3 — Controlled Authorized Assessment Orchestration & Runtime Safety Certification Walkthrough

**Phase:** Phase 15 — Step 3  
**Module:** Controlled Authorized Assessment Orchestration & Runtime Safety Certification  
**Repository:** `C:/Users/sujal/OneDrive/Documents/Desktop/Aihax`  
**Certification Status:** **100% PASSED (PRODUCTION-CERTIFIED & SEALED)**  
**Network Isolation:** Strict Loopback / Mock-Only (`127.0.0.1`, `localhost`, `::1`). Zero external network calls.

---

## 1. Orchestration Architecture Overview

AihaX Phase 15 Step 3 hardens and certifies the production execution orchestration pipeline. Every automated assessment executes strictly through a deterministic, fail-closed safety chain:

```
EXPLICIT AUTHORIZATION
       ↓
CONCRETE TARGET URL
       ↓
ACTIVE AUTHORIZATION RECORD
       ↓
VALID SCOPE SNAPSHOT (SHA-256)
       ↓
EXECUTION PLAN (CRYPTOGRAPHIC SEAL)
       ↓
DESTINATION SAFETY GATE
       ↓
SERVER-SIDE BUDGET ACCOUNTING
       ↓
REQUESTENGINE GATE
       ↓
REGISTERED NON-DESTRUCTIVE CHECK
       ↓
EVIDENCE VAULT (CONTENT-ADDRESSED & REDACTED)
       ↓
VERIFICATION ENGINE
       ↓
CANDIDATE / VERIFIED FINDING
       ↓
SEALED REPORT & AUDIT TRAIL
```

No assessment check can execute without an active, non-expired authorization, an uncorrupted scope snapshot, a valid cryptographic execution plan, concrete URL validation, destination safety verification, and centralized routing through `RequestEngine`.

---

## 2. Complete Certified Execution Pipeline Diagram

```mermaid
flowchart TD
    A["Operator Creates Campaign (Concrete Target)"] --> B["Scope Validation & Snapshot (SHA-256)"]
    B --> C["Operator Records Authorization (ACTIVE, Expiration)"]
    C --> D["Deterministic ExecutionPlan Generated & Hashed"]
    D --> E["Campaign Transition to RUNNING"]
    E --> F["Atomic Task Claiming by CampaignWorker"]
    F --> G{"Pre-Execution Safety Gates"}
    G -- "Expired / Tampered / Out-of-Scope" --> H["Fail Closed / Abort Task / Log Audit"]
    G -- "Passed" --> I{"Destination Safety Check"}
    I -- "Metadata / SSRF" --> J["Block Destination & Log Audit"]
    I -- "Safe" --> K{"Server-Side Budget Check"}
    K -- "Exhausted" --> L["Fail Task & Log Budget Event"]
    K -- "Available" --> M["RequestEngine Centralized Dispatch"]
    M --> N["Execute Registered Non-Destructive Check"]
    N --> O["Evidence Vault (Sanitization & SHA-256 Hashing)"]
    O --> P["VerificationEngine (Truthful Finding Verification)"]
    P --> Q["Task Completion & Natural Campaign Lifecycle"]
    Q --> R["PDF Report & Cryptographic Evidence Manifest"]
```

---

## 3. Execution Plan Abstraction, Schema & Cryptographic Hashing

The `ExecutionPlan` dataclass enforces deterministic check execution order and parameters:

```python
@dataclass
class ExecutionPlanCheck:
    check_id: str
    enabled: bool = True
    destructive: bool = False
    execution_order: int = 1
    timeout_seconds: int = 30
    expected_request_budget: int = 20
    check_version: str = "1.0.0"

@dataclass
class ExecutionPlan:
    campaign_id: str
    target_url: str
    authorized_scope_hash: str
    authorization_id: str
    created_at: str
    checks: List[ExecutionPlanCheck] = field(default_factory=list)
    budget_snapshot: Dict[str, Any] = field(default_factory=dict)
    plan_hash: str = ""

    def compute_hash(self) -> str:
        canonical = {
            "campaign_id": self.campaign_id,
            "target_url": self.target_url,
            "authorized_scope_hash": self.authorized_scope_hash,
            "authorization_id": self.authorization_id,
            "checks": [c.to_dict() for c in self.checks],
            "budget_snapshot": self.budget_snapshot,
        }
        raw = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
```

- Canonical JSON representation guarantees identical SHA-256 hashes across runtime environments.
- Stored inside `CampaignSnapshot.snapshot_json` under `"execution_plan"` and sealed into `campaign.config_hash`.

---

## 4. Pre-Execution Plan Validation & Safety Gates

Before any campaign starts or any worker executes a task, the service performs the complete validation sequence in `validate_execution_plan(campaign_id)`:
1. Snapshot JSON integrity verified against `snapshot.snapshot_hash`.
2. Plan check IDs verified to exist in `CheckRegistry`.
3. Check contract verified to have `destructive == False`.
4. Cryptographic hash recomputed and verified against `plan.plan_hash` and `campaign.config_hash`.
5. Any tampering or mismatch immediately raises `ScopeMismatchException` and blocks campaign start.

---

## 5. Check Execution State Machine & Lifecycle

- **PENDING:** Task created and queued for execution.
- **CLAIMED:** Atomically claimed with short lease (e.g. 30s) and worker heartbeat.
- **RUNNING:** Pre-execution safety gates passed, check executing via `RequestEngine`.
- **COMPLETED:** Check execution finished, findings processed, evidence vaulted.
- **FAILED:** Fail-closed on scope mismatch, expired auth, budget exhaustion, or destination safety.
- **CANCELLED:** Immediately invalidated on operator cancellation; cannot resurrect.

---

## 6. Mid-Run Authorization Revalidation & Fail-Closed Behavior

Inside `CampaignWorker.execute_task`:
1. Authoritative campaign record is queried from database.
2. If `campaign.status != RUNNING` (e.g. `PAUSED` or `CANCELLED`), worker aborts immediately and releases task lease.
3. `_verify_authorization_or_raise` verifies:
   - Authorization status is `ACTIVE`.
   - `expires_at > datetime.now(UTC)`.
   - Snapshot hash matches computed SHA-256.
   - Execution plan hash matches computed SHA-256.
   - Target URL matches scope hash.
4. If any condition is violated, task fails closed and `repo.fail_task` is committed.

---

## 7. Server-Side Request Budget & Concurrency Controls

- `campaign_budget`, `target_budget`, and `check_budget` are enforced on the backend.
- Before issuing requests, worker verifies `campaign.requests_used < campaign.campaign_budget`.
- If budget limit is reached:
  - Task is marked failed with `"Campaign request budget exhausted"`.
  - Structured audit event `BUDGET_EXHAUSTED` is appended.
  - Zero target requests are dispatched.

---

## 8. Cancellation, Task Invalidation & Anti-Resurrection Guarantees

When an operator cancels a campaign via `ops.cancel_campaign(campaign_id)`:
1. Campaign state immediately transitions to `CANCELLED`.
2. All `PENDING`, `CLAIMED`, and `RUNNING` tasks are immediately updated to `CANCELLED`.
3. All worker leases are atomically revoked.
4. Target assignments are released back to available pool.
5. If a worker attempts to process a task from a cancelled campaign, execution aborts with `status: "aborted"`.
6. Stale lease recovery routines explicitly skip cancelled campaigns, guaranteeing **zero task resurrection**.

---

## 9. Evidence Boundary, Redaction & Hash-Chaining

- **`EvidenceVault`:** Central repository for all scan evidence.
- **Secret Redaction:** `redact_secrets` automatically redacts sensitive authorization tokens, API keys, and session cookies from raw requests and responses prior to hash calculation or persistence.
- **Content Hashing:** SHA-256 computed over sanitized request, response, method, target URL, and payload summary.
- **Chain Hashing:** Chained SHA-256 hashes connect sequential observations within a campaign.

---

## 10. Candidate Finding Creation & VerificationEngine Integration

- When a check observes an anomaly, a **Candidate Finding** is created with status `CANDIDATE`.
- Candidate findings pass through `VerificationEngine.verify_finding(finding, req_engine)`.
- If deterministic reproduction confirms the vulnerability, status transitions to `VERIFIED`.
- If reproduction fails or indicates benign behavior, status is set to `INCONCLUSIVE` or `REJECTED`.
- Zero false positives are promoted to verified status without reproduction.

---

## 11. Cryptographic Manifest Generation & Report Sealing

- `ManifestBuilder` computes a top-level Merkle root over:
  - `campaign_id`
  - `scope_hash`
  - `config_hash`
  - `evidence_hashes`
  - `finding_hashes`
  - `report_hashes`
- Report generator outputs compliant executive PDF summaries with magic header `%PDF-`.

---

## 12. Audit Trail Event Schema & Structured Logging

All security-critical actions append an immutable `AuditTrailEvent` containing:
- `campaign_id`
- `event_type` (`EXECUTION_PLAN_CREATED`, `CHECK_STARTED`, `CHECK_COMPLETED`, `CHECK_FAILED`, `DESTINATION_SAFETY_BLOCKED`, `BUDGET_EXHAUSTED`, `CAMPAIGN_CANCELLED`, `CAMPAIGN_PAUSED`, `CAMPAIGN_RESUMED`)
- `actor` (`operator_id`, `worker_id`, or `system`)
- `object_id` (Task ID or Authorization ID)
- `metadata` (JSON payload with structured error details, target URLs, and hash seals)
- `timestamp` (UTC datetime)

---

## 13. API Endpoint Hardening & Responses

- `/api/campaigns/{id}/preflight`: Returns structured pre-flight safety and authorization checklist.
- `/api/campaigns/{id}/runtime-truth`: Provides diagnostic runtime truth state.
- `/api/campaigns/{id}/start`: Enforces authorization, execution plan integrity, and concrete URL validation before launching.
- `/api/campaigns/{id}/cancel`: Atomically terminates running tasks and releases target leases.

---

## 14. Operator UI Execution Readiness Display

`NewAssessment.jsx` renders a pre-flight execution readiness card verifying:
- Concrete Target: Validated HTTP/HTTPS URL
- Authorized Scope: In-Scope Match
- Active Authorization: Operator Signature & Duration
- Scope Snapshot: SHA-256 Verified Seal
- Destination Safety: Metadata & Link-Local Blocked
- Execution Plan: Deterministic & Validated
- Server Budget: Max Requests Configured
- Transport Gate: RequestEngine Active

---

## 15. Static Network Bypass Certification Summary

AST static analysis scanned all 77 check modules in `backend/agents/checks/`:
- **Scanned Modules:** 77 (`C001` through `C077`)
- **Direct Sockets:** 0
- **Direct Requests / Urllib / Urllib3:** 0
- **Direct Httpx / Aiohttp:** 0
- **Subprocess / CLI Calls:** 0
- **Network Bypass Violations:** **0**

---

## 16. Safety Isolation & Zero-External-Network Guarantee

- All automated tests run against loopback fixtures (`127.0.0.1`, `localhost`, `::1`) or `MockTransport`.
- `StrictLoopbackGuardTransport` actively aborts and records any attempted external requests.
- External Network Calls During Verification: **0**

---

## 17. Automated Test Suite Structure & Results

### Backend Test Results (`pytest`)
- **Total Tests Passed:** **673 / 673**
- **Phase 15 Step 3 Tests (`test_phase15_step3_orchestration.py`):** 10 / 10 passed
- **Phase 15 Step 2 Tests (`test_phase15_execution_boundary.py`):** 9 / 9 passed
- **Phase 14 Production Safety Tests (`test_phase14_production_safety.py`):** 14 / 14 passed
- **Phase 13 Lifecycle & Cancellation Tests (`test_lifecycle_and_cancellation.py`):** 22 / 22 passed
- **Failures:** 0

### Frontend Test Results (`vitest`, `eslint`, `vite build`)
- **Vitest Unit & UI Tests:** **40 / 40 passed**
- **ESLint Errors:** **0 errors**
- **Production Build:** Clean (built in 2.19s, zero errors)

---

## 18. 35-Point Safety Verification Results

Execution of `scripts/verify_phase15_step3_orchestration.py`:

```text
===========================================================================
AihaX Phase 15 Step 3 — Controlled Authorized Assessment Orchestration
Runtime Safety & Execution Plan Certification
===========================================================================
[+] [01/35] [PASS] Program registered: prog-phase15-step3-001
[+] [02/35] [PASS] Program scope registered with in-scope and out-of-scope boundaries
[+] [03/35] [PASS] Concrete target URL validated: http://127.0.0.1:8080
[+] [04/35] [PASS] Wildcard target '*.example.com' strictly rejected as executable URL
[+] [05/35] [PASS] Out-of-scope target rejected: URL matches out-of-scope URL rule 'http://127.0.0.1:8080/admin/*'
[+] [06/35] [PASS] Authorization record created: 4a9d7afe-661e-4521-9fae-d54fc9e81c09 (Status: ACTIVE)
[+] [07/35] [PASS] Authorization expiration validated: 2026-09-12T16:14:11.256590+00:00
[+] [08/35] [PASS] Immutable campaign snapshot created: e889b96ee178959a...
[+] [09/35] [PASS] Snapshot SHA-256 seal verified: Snapshot integrity verified
[+] [10/35] [PASS] Deterministic ExecutionPlan created with 1 checks
[+] [11/35] [PASS] ExecutionPlan cryptographic hash verified: a6583a34850cfe92...
[+] [12/35] [PASS] Campaign started and transitioned to RUNNING: 2d246575-5856-4d33-9a29-b758a7d28824
[+] [13/35] [PASS] Worker atomically claimed task: ffa579ef-de2e-4b68-9694-64dbc840cb5f (Check: C049_Clickjacking)
[+] [14/35] [PASS] Pre-execution authorization revalidated successfully
[+] [15/35] [PASS] Pre-execution scope validated: IN_SCOPE
[+] [16/35] [PASS] Destination safety validated: Destination is safe
[+] [17/35] [PASS] Server-side budget available: 0/10
[+] [18/35] [PASS] RequestEngine dispatched check request: http://127.0.0.1:8080
[+] [19/35] [PASS] Evidence persisted in EvidenceVault: count=1
[+] [20/35] [PASS] Evidence SHA-256 content hashes verified
[+] [21/35] [PASS] Finding candidates created: count=1
[+] [22/35] [PASS] Finding verification status validated via VerificationEngine
[+] [23/35] [PASS] Executive PDF report generated: 2526 bytes
[+] [24/35] [PASS] Cryptographic evidence manifest built: 940f128f60580c06...
[+] [25/35] [PASS] Campaign completed naturally: status=COMPLETED
[+] [26/35] [PASS] Expired authorization fail-closed gate verified
[+] [27/35] [PASS] Snapshot tampering detection fail-closed gate verified
[+] [28/35] [PASS] Budget exhaustion fail-closed gate verified
[+] [29/35] [PASS] Cancellation anti-resurrection and task invalidation verified
[+] [30/35] [PASS] Cloud metadata redirect blocking verified
[+] [31/35] [PASS] Out-of-scope redirect blocking verified
[+] [32/35] [PASS] Pause and resume authorization gating verified
[+] [33/35] [PASS] Concurrent budget protection verified (used: 1 <= 10)
[+] [34/35] [PASS] Static network bypass scan: 0 violations across all 77 checks
[+] [35/35] [PASS] Strict zero external network assertion verified: 0 calls

------------------------------------------------------------
SUMMARY: 35/35 CHECKPOINTS PASSED
Active checks: 77
Execution plans validated: 100%
Authorization gates validated: 100%
Scope gates validated: 100%
Destination safety gates validated: 100%
Budget gates validated: 100%
Cancellation invariants validated: 100%
Evidence ownership validated: 100%
Finding verification validated: 100%
Static bypass violations: 0
External network calls: 0
------------------------------------------------------------
FINAL VERDICT: PASS — Controlled authorized execution orchestration verified.
```

---

## 19. Regression Verification Matrix

| Verification Suite | Checkpoints | Result | External Calls |
| :--- | :--- | :--- | :--- |
| **Phase 15 Step 3 Verification** | 35 / 35 | **PASS** | 0 |
| **Phase 15 Step 2 Execution Boundary** | 77 checks | **PASS** | 0 |
| **Phase 14 Production Safety** | 25 / 25 | **PASS** | 0 |
| **Phase 13 E2E Runtime Truth** | 10 / 10 | **PASS** | 0 |
| **Full Pytest Suite** | 673 / 673 | **PASS** | 0 |
| **Vitest Frontend Unit Suite** | 40 / 40 | **PASS** | 0 |
| **Frontend ESLint** | 0 Errors | **PASS** | 0 |
| **Frontend Vite Production Build** | Clean | **PASS** | 0 |

---

## 20. Final Certified Production Assessment Readiness Verdict

**FINAL VERDICT:** **PASS — PRODUCTION-CERTIFIED & SEALED**

AihaX Phase 15 Step 3 has demonstrated with complete empirical evidence that:
1. Every executable target assessment requires explicit, active, non-expired operator authorization.
2. Execution plans are deterministically constructed, cryptographically sealed, and validated fail-closed.
3. Check dispatch is strictly gated through `RequestEngine` with zero bypasses across all 77 registered checks.
4. Destination safety, budget accounting, scope boundaries, and anti-resurrection guarantees are enforced at every step.
5. All automated verification was completed with **zero unauthorized external network requests**.
