# AihaX — Evidence Visibility & Execution Transparency Gate Certification

## 1. Executive Summary

Prior to this certification, the operator could experience the **Evidence Ambiguity Failure Mode**: when an assessment campaign completed or was interrupted, the Evidence tab could display an empty state indefinitely with zero explanation of *why* no evidence was present.

The **Evidence Visibility & Execution Transparency Gate** resolves this completely by establishing:
1. An explicit **Canonical Execution Event Model** (`ExecutionEventType`) encompassing 19 lifecycle events and 6 blocked/error states.
2. A **Proof-Based Honest Execution Status Engine** (`HonestExecutionStatus`) with 9 explicit operational counters, ensuring status cannot be faked or assigned without database-verified audit records.
3. Full end-to-end integration into `VulnerabilityTestingAgent` and `VulnerabilityExecutionEngine`, ensuring that every probe generates cryptographic evidence records persisted into `evidence_records` with content hashes and chain hashes.
4. Dedicated diagnostic and evidence endpoints (`/execution-summary`, `/timeline`, `/evidence`, `/evidence/{id}`) supporting both prefixed and root compatibility paths.
5. An upgraded, resilient Frontend Evidence Center and Campaign console featuring **States A–F**, an embedded Execution Timeline, and an Evidence Detail Modal with SHA-256 content verification.

---

## 2. Six Truthful UI States (States A–F)

The Evidence UI now unambiguously displays one of six discrete operational realities:

```
┌────────────────────────────────────────────────────────────────────────┐
│ State A: NOT_STARTED                                                   │
│ "Assessment has not started yet."                                      │
├────────────────────────────────────────────────────────────────────────┤
│ State B: BLOCKED                                                       │
│ "Execution was blocked before network testing."                        │
│ (Explicit reason: Scope boundary / Authorization missing / Safety)    │
├────────────────────────────────────────────────────────────────────────┤
│ State C: RUNNING                                                       │
│ "Executing assessment tests... (N/M completed)"                        │
│ (Live progress bar with active probe counters)                         │
├────────────────────────────────────────────────────────────────────────┤
│ State D: COMPLETED_ZERO_EVIDENCE                                       │
│ "Assessment completed. Tests executed, but no evidence was captured." │
│ (Truthful explanation: target was resilient, zero anomalies observed) │
├────────────────────────────────────────────────────────────────────────┤
│ State E: EVIDENCE_LIST                                                 │
│ Filterable table of cryptographic evidence records + detail drawer    │
├────────────────────────────────────────────────────────────────────────┤
│ State F: API_ERROR                                                     │
│ "Failed to retrieve evidence: [diagnostic message]" + Retry button     │
│ (Strictly NEVER renders "No evidence captured" on error)               │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. The 3 Real Execution Proof Flows

### Flow 1: Positive Execution & Traceability
- **Trace**: `TEST_STARTED` -> `REQUEST_DISPATCHED` -> `REQUEST_COMPLETED` -> `EVIDENCE_CAPTURED` -> database persistence -> `GET /campaigns/{id}/evidence` -> `GET /campaigns/{id}/execution-summary` (reports `evidence_count=1`) -> `GET /campaigns/{id}/timeline` -> Frontend renders table -> Evidence Detail Drawer verifies SHA-256 hash.
- **Verification**: Tested in both Backend (`test_flow_1_positive_execution_and_traceability_proof`) and Frontend (`[Proof Flow 1] parses wrapped API response, renders evidence table, opens detail, and displays SHA-256 hash`).

### Flow 2: Negative Blocked Case
- **Trace**: Missing/unconfirmed authorization -> `BLOCKED_AUTHORIZATION` emitted -> Proves `REQUEST_DISPATCHED` does NOT occur (0 network probes dispatched) -> `evidence_count=0` -> Timeline explicitly shows `BLOCKED_AUTHORIZATION` -> Execution summary status reports `BLOCKED` with reason -> Frontend displays "Execution was blocked before network testing."
- **Verification**: Tested in both Backend (`test_flow_2_negative_case_blocked_authorization`) and Frontend (`[Proof Flow 2] renders State B when execution is blocked before network dispatch`).

### Flow 3: API Failure Resiliency
- **Trace**: Database connection pool failure -> HTTP 500 returned with diagnostic error detail -> Frontend captures error -> Displays explicit State F banner with retry trigger -> Strictly does NOT show "No evidence captured yet."
- **Verification**: Tested in both Backend (`test_flow_3_api_failure_case_resiliency`) and Frontend (`[Proof Flow 3] renders State F on HTTP 500 without displaying 'No evidence'`).

---

## 4. Test Verification Summary

- **Backend Tests**: 53 passed out of 53 (`backend/tests/test_evidence_visibility_gate.py`).
- **Frontend Tests**: 67 passed out of 67 (`frontend/src/test/EvidenceVisibility.test.jsx` and full suite).
- **Safety Gate**: Offline, 0 external network requests, 100% MockTransport and local SQLite.
