# AihaX Evidence Lifecycle & Traceability Architecture

## 1. End-to-End Lifecycle Trace

Every security check and exploratory probe in AihaX traverses a strict, observable multi-stage pipeline:

```mermaid
sequenceDiagram
    autonumber
    participant Agent as VulnerabilityTestingAgent
    participant Hypo as VulnerabilityHypothesisEngine
    participant Exec as VulnerabilityExecutionEngine
    participant Safe as RequestEngine (Mock/Safe)
    participant Vault as EvidenceVault
    participant DB as SQLite / Persistence DB
    participant API as FastAPI Router (/campaigns)
    participant Client as Frontend API (api.js)
    participant UI as Evidence / Campaigns UI

    Agent->>Hypo: 1. Generate hypotheses from Attack Surface
    Hypo-->>Agent: Bounded Hypotheses (target, endpoint, check_id)
    Agent->>Exec: 2. Execute hypothesis (mode, campaign_id)
    Exec->>Safe: 3. Dispatch safe HTTP probe (RequestSpec)
    Safe-->>Exec: 4. Probe response (status, headers, body)
    Exec->>Exec: 5. Differential analysis & SHA-256 hash
    Exec-->>Agent: 6. VulnerabilityExecutionEvidence
    Agent->>Vault: 7. store_evidence(campaign_id, raw_req, raw_res)
    Vault->>DB: 8. Insert EvidenceRecord + AuditTrailEvent
    Client->>API: 9. GET /api/campaigns/{id}/evidence
    API->>DB: 10. Query EvidenceRecords by campaign_id
    DB-->>API: EvidenceRecord rows
    API-->>Client: 11. { success: true, data: { items: [...], total_count } }
    Client-->>UI: 12. Unpack wrapped data.items
    UI-->>UI: 13. Render Evidence Table & SHA-256 Hash
```

---

## 2. Granular Stage Responsibilities

### Stage 1: Hypothesis Framing & Test Selection
- **Module**: `VulnerabilityTestSelector` & `VulnerabilityHypothesisEngine`
- **Output**: `VulnerabilityHypothesis` bound to `campaign_id`, target endpoint, HTTP method, account role, and safety budget.
- **Audit Event**: `HYPOTHESIS_CREATED`

### Stage 2: Safe Request Dispatch
- **Module**: `RequestEngine` + `MockTransport` (Local/Offline)
- **Constraints**: Destination safety check (blocks metadata/loopback/cloud internal), scope validation (HackerOne in-scope wildcards), and rate limiter.
- **Audit Events**: `TEST_STARTED`, `REQUEST_DISPATCHED`, `REQUEST_COMPLETED`

### Stage 3: Differential Analysis & Cryptographic Hashing
- **Module**: `VulnerabilityExecutionEngine`
- **Integrity**: Computes SHA-256 over canonical probe response and differential comparison.
- **Audit Event**: `EVIDENCE_CAPTURED`

### Stage 4: Secret Redaction & Vault Persistence
- **Module**: `EvidenceVault` (`backend/evidence/evidence_store.py`)
- **Sanitization**: All HTTP headers (`Authorization`, `Cookie`, `X-Api-Key`), request body credentials, and query tokens are replaced with `[REDACTED]`.
- **Persistence**: Persisted to `evidence_records` table with foreign key `campaign_id`. Chained hash computed against previous campaign artifact.
- **Audit Event**: `AuditTrailEvent` persisted to `audit_trail_events`.

### Stage 5: Verification & Quality Gate
- **Module**: `FindingQualityGate` + `VerificationEngine`
- **Association**: Finding is linked directly to `evidence_record.id` via `finding_id`.
- **Audit Events**: `VERIFICATION_COMPLETED`, `FINDING_CREATED`, `QUALITY_GATE_COMPLETED`

### Stage 6: Diagnostic & Evidence API
- **Endpoints**:
  - `GET /api/campaigns/{id}/evidence` (and `/campaigns/{id}/evidence`): Returns wrapped structure `{ success: true, data: { items: [...], total_count, campaign_id } }`.
  - `GET /api/campaigns/{id}/evidence/{evidence_id}`: Returns secret-redacted detail record with SHA-256 hash.
  - `GET /api/campaigns/{id}/execution-summary`: Returns proven status and 9 test counters.
  - `GET /api/campaigns/{id}/timeline`: Returns chronological event stream with event hashes.

### Stage 7: Frontend Consumption & Presentation
- **Client**: `frontend/src/lib/api.js`
- **Parser**: Resilient extraction handles both array and wrapped object shapes:
  ```javascript
  const rawData = res.data?.data ?? res.data ?? [];
  const list = Array.isArray(rawData) ? rawData : (Array.isArray(rawData?.items) ? rawData.items : []);
  ```
- **UI Views**:
  - **State A**: No execution started.
  - **State B**: Execution blocked before network dispatch (scope, auth, safety).
  - **State C**: Execution running with live progress counter.
  - **State D**: Execution completed with zero evidence.
  - **State E**: Loaded evidence records with modal preview.
  - **State F**: Evidence API failure banner with diagnostic message and Retry button.
  - **Timeline Tab**: Embedded chronological event log showing every check probe and transition.
