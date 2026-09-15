# AihaX Phase 17 — First Real Authorized Bug-Bounty Assessment Walkthrough

## Executive Summary

Phase 17 represents the culmination of all previous AihaX safety and execution phases into an authorized, certified engine capable of executing **one real, non-destructive bug-bounty assessment** against **one concrete target URL** belonging to an imported HackerOne scope (**Xiaomi — HackerOne**).

---

## 1. System Invariants & Proof Points

| Invariant | Implementation Mechanism | Verification Result |
|---|---|---|
| **Wildcards are Authorization Rules Only** | `BugBountyScopeAsset` preserves raw and normalized rules (`*.xiaomi.com`), `validate_concrete_target_url` rejects wildcard inputs. | [PASS] 100% |
| **Single Concrete Target URL** | `create_production_campaign` accepts exactly one concrete URL or enters `WAITING_FOR_TARGET`. | [PASS] 100% |
| **WAITING_FOR_TARGET State** | Fails closed on launch, blocks task claiming, requires explicit `supply_concrete_target` binding with operator signature. | [PASS] 100% |
| **Destination Safety (Strict Mode)** | Strict SSRF blocks loopback (`127.0.0.1`, `::1`), private RFC1918 IPv4, and cloud metadata (`169.254.169.254`). | [PASS] 100% |
| **Locked Production Profile** | Server-enforced `budget=10`, `concurrency=1`, `rate_limit=2 RPS`, `methods=GET/HEAD/OPTIONS only`. | [PASS] 100% |
| **Unified RequestEngine Boundary** | All execution routes through `RequestEngine` with pre-socket scope and hop-by-hop redirect verification. | [PASS] 100% |
| **Evidence Vault & Secret Redaction** | Redacts credentials prior to SHA-256 content hashing; cryptographically chains observations. | [PASS] 100% |
| **Candidate Finding Lifecycle** | Candidate -> VerificationEngine -> Verified/Rejected lifecycle. | [PASS] 100% |
| **HackerOne Report Integrity** | Strict separation of FACT vs INFERENCE; cryptographic report integrity hashes. | [PASS] 100% |
| **Emergency Kill Switch** | `POST /api/campaigns/{id}/kill` is terminal, atomic, idempotent, cancels all leases, stops workers. | [PASS] 100% |
| **Zero External Network Calls in Tests** | All tests and automated certification utilize `MockTransport` and local fixtures (`external_calls == 0`). | [PASS] 100% |

---

## 2. Operator Execution Procedure

To execute an authorized assessment against a concrete Xiaomi target:

### Step 1: Import HackerOne Xiaomi Program
```bash
POST /api/programs/import
{
  "platform": "hackerone",
  "program_name": "Xiaomi",
  "policy_url": "https://hackerone.com/xiaomi/policy_scopes",
  "in_scope_assets": ["*.xiaomi.com", "*.mi.com", "*.miui.com"],
  "out_of_scope_assets": ["out-of-scope.xiaomi.com"]
}
```

### Step 2: Create Authorized Production Campaign
```bash
POST /api/campaigns
{
  "name": "Xiaomi Account Security Assessment",
  "target_url": "https://account.xiaomi.com",
  "program_id": "<xiaomi_program_id>",
  "authorized_by": "security-lead@example.com",
  "assessment_mode": "PRODUCTION_AUTHORIZED",
  "operator_confirmation": "I confirm this concrete target is authorized under the selected bug-bounty program and I understand this assessment will perform real requests."
}
```

*Note: If created without a target, supply target via `POST /api/campaigns/{id}/target` with the same confirmation.*

### Step 3: Run Preflight Check
```bash
GET /api/campaigns/{id}/preflight
```
Ensure `ready_to_execute: true` and all safety gates report `PASS`.

### Step 4: Dispatch Campaign
```bash
POST /api/campaigns/{id}/start
```
The campaign worker claims tasks, dispatches safe HTTP requests (max 10 requests, concurrency 1, rate 2 RPS), logs evidence to the vault, and verifies findings.

### Step 5: Export HackerOne Report
```bash
GET /api/reports/campaigns/{id}/hackerone
```
Produces a structured report formatted for HackerOne submission with strictly separated facts and inferences.

---

## 3. Test & Certification Results

```
============================================================
AihaX Phase 17 Certification Verification
============================================================
All 52/52 Checkpoints: PASSED (100%)
Unit Test Suite: 49/49 Tests PASSED (backend/tests/test_phase17_first_real_assessment.py)
Full Backend Regression: 828/828 Tests PASSED (0 failures)
Frontend Unit Suite: 40/40 Tests PASSED (0 failures, 0 lint errors)
Historical Certifications: 100% PASSED (Phases 13, 14, 15 Step 2-5, 16)
External Network Calls Dispatched: 0
============================================================
```
