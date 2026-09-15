# AihaX Phase 17 — First Real Authorized Bug-Bounty Assessment Specification

## Overview

AihaX Phase 17 certifies the system's capability to execute the **first real, explicitly authorized, non-destructive bug-bounty assessment** against **one concrete target URL** belonging to an imported HackerOne program scope (initial target program: **Xiaomi — HackerOne**).

---

## 1. Core Security Invariants

1. **Wildcards are Authorization Rules Only, Never Executable Targets**:
   - `*.xiaomi.com`, `*.mi.com`, `*.miui.com` define the program's authorization boundary.
   - Any attempt to supply a wildcard (e.g. `*.xiaomi.com` or `https://*.xiaomi.com`) as an execution target is rejected immediately with `ValueError`.
2. **Exactly One Concrete Target Per Campaign**:
   - Multiple comma-separated targets, CIDR blocks, or wildcard inputs fail closed.
   - Initial authorized target: `https://account.xiaomi.com`.
3. **WAITING_FOR_TARGET State Integrity**:
   - When a production campaign is initialized without a target (`target_url=None`), the campaign enters `awaiting_target=True` and `target_url="WAITING_FOR_TARGET"`.
   - While in `WAITING_FOR_TARGET`, preflight checklist fails closed, campaign launch is blocked, and worker task claims return 0 tasks.
   - Binding requires operator confirmation via `POST /api/campaigns/{id}/target` or `supply_concrete_target()`.
4. **Destination Safety & SSRF Protection (Strict Mode)**:
   - In `PRODUCTION_AUTHORIZED` mode (`allow_loopback=False`), all private IPv4/IPv6 networks, localhost, `127.0.0.1`, `::1`, and cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`) are blocked.
   - Non-HTTP schemes (`file://`, `ftp://`, `gopher://`) are rejected.
5. **Server-Enforced Conservative Production Profile**:
   - `campaign_budget`: 10 requests maximum (locked server-side).
   - `max_concurrency`: 1 worker (locked server-side).
   - `rate_limit_rps`: 2 requests per second maximum (locked server-side).
   - `allowed_methods`: `GET`, `HEAD`, `OPTIONS` only (mutating HTTP methods `POST`, `PUT`, `PATCH`, `DELETE` are blocked).
6. **Unified Central Socket Boundary (RequestEngine)**:
   - All network traffic flows strictly through `RequestEngine`.
   - Every request is gated by active authorization, destination safety, and in-scope checks.
   - Redirect chains are re-validated hop-by-hop before dispatch.
7. **Secret Redaction & Cryptographic Evidence Vault**:
   - All authorization tokens, cookies, and credentials are redacted prior to SHA-256 content hashing and persistence.
   - Sequential observations are cryptographically linked using chained SHA-256 hashes.
8. **Candidate Finding Verification**:
   - Findings start as `CANDIDATE` and require deterministic verification via `VerificationEngine` before being classified as `VERIFIED`.
9. **HackerOne Report Integrity**:
   - Reports strictly separate **FACT** (evidence-backed HTTP observations) from **INFERENCE** (theoretical impact assessments).
   - Cryptographic hashes seal report integrity.
10. **Tamper-Evident Audit Trail & Emergency Kill Switch**:
    - Every lifecycle event is recorded in a cryptographically linked SHA-256 event hash chain.
    - Kill switch (`POST /api/campaigns/{id}/kill`) is atomic, idempotent, cancels all active leases, and transitions the campaign to terminal `KILLED` state.
11. **Zero External Network Calls in Testing**:
    - All automated tests and certification checkpoints run against deterministic mock transports and fixtures with `external_network_calls == 0`.

---

## 2. Architecture & Workflow

```
HackerOne Program (Xiaomi)
          │
          ▼
   Program Scope (Rules: *.xiaomi.com, *.mi.com, *.miui.com)
          │
          ▼
Authorization Record (Active, Valid Expiry, Operator Signature)
          │
          ▼
Immutable Scope Snapshot (SHA-256 Sealed)
          │
          ▼
Production Campaign (DRAFT / WAITING_FOR_TARGET)
          │
   [Operator Supplies Concrete Target: https://account.xiaomi.com]
          │
          ▼
Destination Safety + Scope Validation + Non-Destructive Execution Plan
          │
          ▼
Preflight Checklist (100% Passed)
          │
          ▼
Worker Execution (Budget=10, Concurrency=1, Rate=2 RPS, GET/HEAD/OPTIONS)
          │
          ▼
Evidence Vault (Redacted Secrets, SHA-256 Chain)
          │
          ▼
Verification Engine (Candidate -> Verified / Rejected)
          │
          ▼
HackerOne Report (FACT vs INFERENCE) + Tamper-Evident Audit Trail
```

---

## 3. Audit Trail Event Types

- `PROGRAM_IMPORTED`
- `AUTHORIZATION_CONFIRMED`
- `PRODUCTION_CAMPAIGN_CREATED`
- `TARGET_SUPPLIED`
- `TARGET_SCOPE_VALIDATED`
- `DESTINATION_SAFETY_PASSED`
- `ASSESSMENT_PREFLIGHT`
- `EXECUTION_STARTED`
- `CHECK_STARTED`
- `REQUEST_DISPATCHED`
- `EVIDENCE_RECORDED`
- `FINDING_CANDIDATE`
- `FINDING_VERIFIED`
- `FINDING_REJECTED`
- `EXECUTION_COMPLETED`
- `REPORT_GENERATED`
- `CAMPAIGN_KILLED`

---

## 4. Certification Summary

- **Unit Test Suite**: `backend/tests/test_phase17_first_real_assessment.py` (49 tests, 100% pass rate).
- **Certification Script**: `scripts/verify_phase17_first_real_assessment.py` (52 checkpoints, 100% pass rate).
- **Full Backend Regression**: 828 tests passed (100% pass rate).
- **Frontend Test Suite**: 40 tests passed, 0 lint errors, production build clean.
- **Historical Certification**: 100% pass across Phases 13, 14, 15 (Steps 2–5), and 16.
