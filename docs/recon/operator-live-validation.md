# Operator-Initiated Live Recon Validation Workflow Documentation

## Architecture & Overview
The Operator-Initiated Live Recon Validation Workflow provides a desktop-first, human-in-the-loop preflight and confirmation interface in AihaX for reviewing and triggering authorized live reconnaissance runs.

```text
Operator (GUI)
     │
     ▼ [Click: "Run Live Recon Validation"]
GET /api/campaigns/{id}/recon-live-preflight
     │
     ▼ (Advisory Preflight Matrix & Safety Budget)
LiveReconPreflightModal
     │
     ▼ [4 Required Checkboxes Checked + Confirm]
POST /api/campaigns/{id}/recon-live-validation?mode=mock
     │
     ▼
OperatorLiveReconService
     ├── 1. Authoritative Backend Re-validation (Auth, Scope, Capability, Safety)
     ├── 2. Audit Trail Logging (OPERATOR_LIVE_RECON_VALIDATION_MOCK_LAUNCHED)
     └── 3. Mode Routing (mode=mock -> MockExecutionAdapter)
```

---

## Security Invariants & Status Semantics

### Status Semantics
- `AVAILABLE`: Local binary / tool adapter is installed and available locally. Does **NOT** mean live validated.
- `MOCK_VALIDATED`: Controlled dry-run / mock validation execution completed without network calls.
- `LIVE_VALIDATED`: Real, authorized live execution completed through the AihaX controlled pipeline.
- `AUTH_REQUIRED`: Capability exists but active authorization or capability policy opt-in is missing.
- `BLOCKED_POLICY`: Operation intentionally prohibited by policy.
- `BLOCKED_SCOPE`: Target failed scope validation.
- `BLOCKED_SAFETY`: Blocked by anti-SSRF or destination safety controls.
- `UNAVAILABLE`: Executable binary not found on system PATH.
- `STUB_ONLY`: Capability not yet implemented in production.

### Invariant Guarantees
$$\text{AVAILABLE} \neq \text{MOCK\_VALIDATED} \neq \text{LIVE\_VALIDATED}$$

- Read-only preflight evaluation (`GET /recon-live-preflight`) generates **0 network traffic**.
- Mock mode (`mode=mock`) **NEVER** generates `LIVE_VALIDATED` records or mutates historical evidence.
- Frontend checkboxes are UX advisory controls only; the backend authoritatively re-validates all security preconditions on every POST request.

---

## API Endpoints

### 1. Read-Only Advisory Preflight
`GET /api/campaigns/{campaign_id}/recon-live-preflight`
- **Auth**: Required
- **Method**: `GET`
- **Response**:
  - `authorization`: Active status, ID, authorized_by, expires_at
  - `scope`: Scope snapshot hash & validation status
  - `permitted_capabilities`: Passive recon, controlled discovery, service discovery, content discovery, vulnerability detection, active testing flags
  - `safety_budget`: Concurrency (1), rate limit (<=2 RPS), HTTP methods (GET/HEAD/OPTIONS), disabled actions list
  - `tool_matrix`: 14 registered tools mapped to capability class, installation status, auth permission, and readiness status
  - `can_launch`: Boolean

### 2. Validation Run Submission
`POST /api/campaigns/{campaign_id}/recon-live-validation?mode=mock`
- **Auth**: Required
- **Method**: `POST`
- **Query Parameter**: `mode=mock` (Defaults safely to mock)
- **Body**: `{"confirmations": {"authActive": true, "targetCorrect": true, ...}}`
- **Behavior**: Authoritatively re-evaluates preflight. Dispatches `mode=mock` run to `MockExecutionAdapter`. Returns `MOCK_VALIDATED` status per runnable tool. Emits `AuditTrailEvent`.

---

## Phase 28 Statement
> **Phase 28 was not started. No external target traffic was generated during this implementation.**
