# AihaX Execution Observability Model

## 1. Overview & Philosophy

In security assessment systems, an unverified or ambiguous state is indistinguishable from operational failure. Prior to the Evidence Visibility & Execution Transparency Gate, the operator interface could present an empty Evidence Vault without disambiguating whether:
- Execution had not yet been scheduled or dispatched.
- Execution was proactively blocked before network egress by authorization, scope, or safety constraints.
- Execution was actively running.
- Execution ran and completed cleanly without producing findings or evidence.
- An API failure or transport error occurred.
- A serialization bug prevented captured evidence from rendering.

The AihaX Observability Model enforces **Truth in Operational State**: no state transition is allowed without cryptographic or operational evidence anchored in the database audit log.

---

## 2. Canonical Execution Events (`ExecutionEventType`)

Every campaign assessment execution cycle emits deterministic lifecycle and boundary events:

| Event Type | Category | Description | Required Metadata |
|---|---|---|---|
| `CAMPAIGN_CREATED` | Lifecycle | Campaign initialized in draft or staged state | Target, mode, initial budget |
| `PREFLIGHT_STARTED` | Lifecycle | Beginning mandatory scope and environmental pre-checks | Scope targets, token validity |
| `PREFLIGHT_COMPLETED` | Lifecycle | All pre-flight checklist conditions verified | Passed checks count |
| `RECON_STARTED` | Lifecycle | Passive & active attack surface discovery begins | Target URL |
| `RECON_COMPLETED` | Lifecycle | Endpoints, assets, and parameters enumerated | Discovered count |
| `VULNERABILITY_SELECTION_STARTED`| Lifecycle | Intelligent selection of applicable check modules | Surface profile |
| `VULNERABILITY_SELECTION_COMPLETED`| Lifecycle | Selection matrix compiled with priority tiers | Applicable, blocked counts |
| `HYPOTHESIS_CREATED` | Lifecycle | Concrete, testable hypothesis framed for an endpoint | Check ID, hypothesis ID |
| `APPROVAL_REQUIRED` | Boundary | Privileged or high-impact probe requires operator sign-off | Action, scope |
| `APPROVAL_RECEIVED` | Boundary | Cryptographic authorization token supplied | Approver ID, token ID |
| `TEST_STARTED` | Lifecycle | Execution of an individual check probe begins | Check ID, endpoint |
| `REQUEST_DISPATCHED` | Lifecycle | HTTP probe transmitted through safe RequestEngine | Request ID, method, target |
| `REQUEST_COMPLETED` | Lifecycle | Probe completed with status and body hash | Status code, latency |
| `EVIDENCE_CAPTURED` | Lifecycle | Artifact cryptographically hashed and saved to vault | Evidence ID, SHA-256 hash |
| `VERIFICATION_COMPLETED` | Lifecycle | Differential analysis and confidence scoring concluded | Verdict, status |
| `FINDING_CREATED` | Lifecycle | Confirmed or candidate finding registered | Finding ID, severity |
| `QUALITY_GATE_COMPLETED` | Lifecycle | Quality & false-positive validation concluded | Verdict, confidence score |
| `REPORT_GENERATED` | Lifecycle | Operator report compiled and sealed | Report hash, size |
| `CAMPAIGN_COMPLETED` | Lifecycle | Full campaign workflow successfully concluded | Execution summary |
| `BLOCKED_SCOPE` | Blocked | Probe halted: target outside HackerOne scope wildcard | Out-of-scope URL, rule |
| `BLOCKED_AUTHORIZATION` | Blocked | Probe halted: missing or expired operator authorization | Scope target, reason |
| `BLOCKED_SAFETY` | Blocked | Probe halted: prohibited destination (metadata, loopback)| Destination IP, safety rule|
| `BLOCKED_BUDGET` | Blocked | Probe halted: campaign request allowance exhausted | Used count, max budget |
| `EXECUTION_ERROR` | Error | Unhandled runtime or worker dispatch exception | Error message |
| `EVIDENCE_PERSISTENCE_ERROR` | Error | Failure to serialize or write evidence artifact | Error message |

---

## 3. Honest Execution Status (`HonestExecutionStatus`)

The campaign execution status is strictly derived from proven backend states and events:

```
[NOT_STARTED]
      │
      ▼
 [PREFLIGHT] ──(Blocked: scope/auth/safety)──► [BLOCKED]
      │
      ▼
   [RECON]
      │
      ▼
[SELECTING_TESTS]
      │
      ▼
[AWAITING_APPROVAL] (for privileged live tests)
      │
      ▼
  [EXECUTING] ◄──► [VERIFYING]
      │
      ├────────────────────────────► [CANCELLED] (by operator)
      ├────────────────────────────► [FAILED] (unhandled error)
      ▼
 [COMPLETED] (Proof: all tasks finished, summary generated)
```

### Nine Quantitative Operational Counters

To prevent ambiguous progress indicators, the execution model exposes 9 explicit integers:
1. `tests_selected`: Total candidate tests approved by selection matrix.
2. `tests_started`: Tests that have commenced execution.
3. `tests_completed`: Tests that reached a terminal state.
4. `tests_blocked`: Tests halted by scope, safety, or authorization rules.
5. `tests_inconclusive`: Tests yielding ambiguous or non-reproducible differential signals.
6. `tests_detected`: Tests where candidate vulnerabilities were observed.
7. `tests_validated`: Tests verified through reproduction and quality gates.
8. `evidence_count`: Total cryptographic artifacts saved in `EvidenceVault`.
9. `finding_count`: Total findings registered in the findings store.

---

## 4. Tamper-Evident Event Hashing & Chaining

Each `ExecutionEvent` computes a cryptographic SHA-256 digest across its immutable properties:
```python
payload = {
    "id": event_id,
    "campaign_id": campaign_id,
    "event_type": event_type,
    "timestamp": timestamp_iso,
    "target_url": target_url,
    "check_id": check_id,
    "test_id": test_id,
    "request_id": request_id,
    "evidence_id": evidence_id,
    "finding_id": finding_id,
    "status": status,
    "reason": clean_reason,
    "metadata": clean_meta,
    "previous_event_hash": previous_hash,
}
event_hash = sha256(canonical_json(payload))
```
This forms an append-only, tamper-evident audit ledger anchored in the SQLite/PostgreSQL persistence layer.
