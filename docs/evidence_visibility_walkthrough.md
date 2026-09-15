# AihaX — Evidence Visibility & Execution Transparency Walkthrough

## 1. Executive Walkthrough Overview

This walkthrough documents the end-to-end verification of the **Evidence Visibility & Execution Transparency Gate**, establishing deterministic proof that assessment executions, boundary conditions, cryptographic artifacts, and operator error states are transparently observable from the database up to the user interface.

---

## 2. Real Execution Proofs (Exact Tests & Assertions)

### Flow 1: Positive Execution & Traceability Flow

**Objective**: Prove complete end-to-end execution, cryptographic hashing, persistence, diagnostic API retrieval, and frontend rendering with SHA-256 integrity.

#### Backend Test
- **Test File**: `backend/tests/test_evidence_visibility_gate.py`
- **Test Name**: `TestRealExecutionProofs.test_flow_1_positive_execution_and_traceability_proof`
- **Assertion Sequence**:
  1. `assert len(result.evidence_references) >= 1` (Execution produced evidence ID)
  2. `assert len(evidence_records) >= 1` (Evidence record persisted into SQLite `evidence_records`)
  3. `assert len(saved_ev.content_hash) == 64` (Valid SHA-256 hex string)
  4. `assert resp_ev.status_code == 200` (`GET /campaigns/{id}/evidence` returned wrapped JSON)
  5. `assert any(it["id"] == saved_ev.id for it in resp_ev.json()["data"]["items"])` (Item present in list)
  6. `assert resp_sum.json()["data"]["evidence_count"] >= 1` (`GET /campaigns/{id}/execution-summary` reports evidence_count)
  7. `assert "EVIDENCE_CAPTURED" in [e["event_type"] for e in resp_time.json()["data"]]` (`GET /campaigns/{id}/timeline` contains event)
  8. `assert resp_det.json()["data"]["content_hash"] == saved_ev.content_hash` (`GET /campaigns/{id}/evidence/{evidence_id}` matches hash)

#### Frontend Test
- **Test File**: `frontend/src/test/EvidenceVisibility.test.jsx`
- **Test Name**: `[Proof Flow 1] parses wrapped API response, renders evidence table, opens detail, and displays SHA-256 hash`
- **Assertion Sequence**:
  1. `await waitFor(() => expect(screen.getByText('evid-flow-01')).toBeDefined())` (Evidence ID rendered in table)
  2. `expect(screen.getByText('POST')).toBeDefined()` (HTTP Method badge displayed)
  3. `fireEvent.click(screen.getByRole('button', { name: /view/i }))` (Operator opens drawer)
  4. `await waitFor(() => expect(screen.getByText('a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0')).toBeDefined())` (SHA-256 content hash verified in drawer)

---

### Flow 2: Negative Case (Blocked Authorization)

**Objective**: Prove that missing or unconfirmed authorization halts execution before any network dispatch, registers `BLOCKED_AUTHORIZATION` in the timeline, sets honest status to `BLOCKED`, and displays State B in the UI.

#### Backend Test
- **Test File**: `backend/tests/test_evidence_visibility_gate.py`
- **Test Name**: `TestRealExecutionProofs.test_flow_2_negative_case_blocked_authorization`
- **Assertion Sequence**:
  1. `assert len(result.findings) == 0` (Zero findings generated)
  2. `assert len(repo.get_evidence_for_campaign(cid)) == 0` (Zero evidence records in DB)
  3. `assert "BLOCKED_AUTHORIZATION" in [e["event_type"] for e in timeline]` (Event registered in timeline)
  4. `assert "REQUEST_DISPATCHED" not in [e["event_type"] for e in timeline]` (Zero HTTP requests dispatched)
  5. `assert sum_data["status"] == "BLOCKED"` (Honest execution status is BLOCKED)
  6. `assert sum_data["evidence_count"] == 0` (Evidence counter is 0)

#### Frontend Test
- **Test File**: `frontend/src/test/EvidenceVisibility.test.jsx`
- **Test Name**: `[Proof Flow 2] renders State B when execution is blocked before network dispatch`
- **Assertion Sequence**:
  1. `await waitFor(() => expect(screen.getByText('Execution was blocked before network testing.')).toBeDefined())`
  2. `expect(screen.getByText(/Missing explicit operator authorization/i)).toBeDefined()`
  3. `expect(screen.queryByRole('table')).toBeNull()` (Table not rendered in blocked state)

---

### Flow 3: API Failure Resiliency Case

**Objective**: Prove that an HTTP 500 error from the evidence endpoint results in an explicit error message and a retry action, strictly avoiding false "No evidence captured" banners.

#### Backend Test
- **Test File**: `backend/tests/test_evidence_visibility_gate.py`
- **Test Name**: `TestRealExecutionProofs.test_flow_3_api_failure_case_resiliency`
- **Assertion Sequence**:
  1. `assert resp.status_code == 500` (FastAPI returns HTTP 500 Internal Server Error)
  2. `assert "Database connection pool exhausted" in resp.json()["detail"]` (Error details surfaced transparently)

#### Frontend Test
- **Test File**: `frontend/src/test/EvidenceVisibility.test.jsx`
- **Test Name**: `[Proof Flow 3] renders State F on HTTP 500 without displaying 'No evidence'`
- **Assertion Sequence**:
  1. `await waitFor(() => expect(screen.getByText(/Failed to load evidence records/i)).toBeDefined())`
  2. `expect(screen.getByText(/Internal Server Error 500/i)).toBeDefined()`
  3. `expect(screen.queryByText(/No evidence captured yet/i)).toBeNull()` (Never displays "No evidence" on failure)
  4. `expect(screen.getByRole('button', { name: /retry/i })).toBeDefined()` (Retry button present and interactive)

---

## 3. Observability Architecture Verification

```
Database (AuditTrailEvent, EvidenceRecord)
   │
   ▼
FastAPI Compatibility Endpoints (/campaigns/{id}/...)
   ├── GET /campaigns/{id}/execution-summary  (HonestExecutionStatus + 9 counters)
   ├── GET /campaigns/{id}/timeline           (CanonicalExecutionEvents + SHA-256)
   ├── GET /campaigns/{id}/evidence           (Wrapped {items: [...], total_count})
   └── GET /campaigns/{id}/evidence/{eid}     (Redacted payload + content_hash)
   │
   ▼
Frontend API (src/lib/api.js)
   ├── Safe array/object extraction
   └── Dedicated query methods
   │
   ▼
Frontend Views (src/pages/Evidence.jsx & src/pages/Campaigns.jsx)
   ├── Six Honest States (A–F)
   ├── Execution Timeline Tab
   └── Secret-Redacted Evidence Modal
```
