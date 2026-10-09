# Full-Port Recon Background Job Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a durable, explicitly confirmed background run that discovers authorized hosts, scans each sequentially on every authorized TCP port except exclusions, and records honest per-host progress and evidence.

**Architecture:** Persist a `ReconLiveRun` and unique `ReconLiveRunHost` children in AihaX's existing SQLAlchemy database. A new runtime discovers and scope-filters hosts, pauses for operator review, then uses the existing recon engine and `ToolExecutionBoundary` to execute one host at a time; API and UI expose review, confirmation, status, and cancellation. Recovery resumes only unfinished hosts and cancellation is propagated to the active subprocess.

**Tech Stack:** Python 3, FastAPI, SQLAlchemy, SQLite migration runner, asyncio subprocesses, React, Axios, pytest, Vitest.

**Spec:** `docs/superpowers/specs/2026-10-07-full-port-recon-job-design.md`

## Global Constraints

- The program's saved in-scope and out-of-scope asset rules remain authoritative for every discovered hostname. Out-of-scope rules override in-scope rules.
- The program's `allowed_ports` must explicitly cover ports 1–65535 before a full TCP scan can be launched; a narrower authorized range is not labeled a full-port scan.
- `excluded_ports` are subtracted from selected ports even if also present in `allowed_ports`.
- Discovery and full-port scanning use two confirmation stages; discovery itself sends no Nmap traffic.
- Run hosts sequentially with one Nmap process at a time; use TCP connect scan (`-sT`), conservative timing (`-T2`), and no NSE, version detection, exploit, or vulnerability probes.
- Every external request/process execution remains behind existing destination-safety, authorization, and `ToolExecutionBoundary` controls.
- Cancellation terminates and reaps the current process, then starts no further host; restart recovery never repeats a host durably marked completed.
- Incomplete, blocked, failed, timed-out, and cancelled work must never be represented as a complete scan.
- Do not run this workflow against a client production target as part of implementation verification; use unit/integration fixtures and local authorized labs only.

## Review Focus

- Scope changes or authorization expiry between discovery, confirmation, and a later host claim: each transition must fail closed; pin in Task 3 and Task 4.
- Empty, malformed, or partially authorized port lists and overlapping exclusions: reject full-scan confirmation and report exact effective count; pin in Task 4 and Task 5.
- Duplicate discovered hostnames, Unicode/case/trailing-dot normalization, and 0 or many hosts: persist each normalized in-scope host once and show a truthful empty-run outcome; pin in Task 1 and Task 3.
- Cancellation racing process completion, worker shutdown, or a new host claim: reap the child and never begin a subsequent host; pin in Task 2 and Task 3.
- Discovery/scan exceptions, oversized tool output, expired worker leases, and database restart: keep durable terminal/partial state and preserve output hashes without repeating completed work; pin in Task 1 and Task 3.

---

### Task 1: Persistent Recon Run and Host Records

**Files:**
- Modify: `backend/persistence/models.py`
- Modify: `backend/models/migrations.py`
- Create: `backend/services/recon_live_run_repository.py`
- Create: `backend/tests/test_recon_live_run_repository.py`
- Modify: `backend/tests/test_phase24_migration_and_models.py` (or add a focused migration test beside it)

**Interfaces:**
- Produces `ReconLiveRun` fields: `id`, `campaign_id`, `authorization_id`, `scope_hash`, `state`, `port_profile`, `allowed_ports_json`, `excluded_ports_json`, `selected_ports_json`, `cancel_requested`, `current_host_id`, `discovered_count`, `completed_count`, `failed_count`, `blocked_count`, `created_at`, `updated_at`, `started_at`, `completed_at`, `failure_detail`.
- Produces `ReconLiveRunHost` fields: `id`, `run_id`, `normalized_host`, `provenance_json`, `scope_decision`, `state`, `host_index`, `execution_id`, `output_hash`, `started_at`, `completed_at`, `failure_detail`; enforce unique `(run_id, normalized_host)`.
- Produces repository operations `create_run(session, run_data)`, `add_hosts(session, run_id, hosts)`, `get_run(session, run_id)`, `list_hosts(session, run_id)`, and atomic `claim_next_host(session, run_id)`; completed hosts are never claimable again.

- [ ] **Step 1: Write failing repository and migration tests** for unique normalized hosts, persistence across new sessions, valid state fields, atomic next-host claims, and migration creating both tables and indexes.
- [ ] **Step 2: Run the focused tests and verify they fail** because the models, migration, and repository do not yet exist.
- [ ] **Step 3: Add the ORM records, migration version 33, and repository operations** in the files above. Serialize snapshot/list data as JSON text; preserve existing migration checksum conventions.
- [ ] **Step 4: Run `pytest backend/tests/test_recon_live_run_repository.py backend/tests/test_phase24_migration_and_models.py -q`** and verify persistence, uniqueness, migration, and claim assertions pass.
- [ ] **Step 5: Commit** as `feat: persist full-port recon runs`.

### Task 2: Cancellable Long-Running Nmap Boundary

**Files:**
- Modify: `backend/execution/tool_execution_boundary.py`
- Modify: `backend/core/config.py`
- Modify: `backend/recon/live_recon_validator.py`
- Create: `backend/tests/test_tool_execution_boundary_cancellation.py`
- Modify: `backend/tests/test_phase25_live_recon_validation.py`

**Interfaces:**
- Extend `ToolExecutionBoundary.execute(request: ToolExecutionRequest, db: Optional[Session] = None, cancel_event: Optional[asyncio.Event] = None) -> ToolExecutionResult` without changing existing callers.
- Add `RECON_FULL_PORT_HOST_TIMEOUT_SECONDS` to `backend/core/config.py`, default `3600`, clamp it to `60..21600`, and set the Nmap tool maximum to `21600`; return existing `TIMEOUT` status when the configured per-host timeout is exceeded.
- The recon Nmap adapter accepts the same optional cancellation event and keeps scan arguments limited to `-sT`, `-T2`, `-p <exact compressed ports>`, and the scope-approved host.

- [ ] **Step 1: Write failing async tests** with a controllable fake subprocess proving cancellation terminates/reaps the process, returns a cancellation result, and does not orphan stdout/stderr reader tasks; test timeout still returns `TIMEOUT`.
- [ ] **Step 2: Run the focused tests and verify they fail** because execute does not yet accept/observe a cancellation event.
- [ ] **Step 3: Implement cancellation-aware waiting and cleanup** in `ToolExecutionBoundary`, cancelling and joining pending readers/process wait tasks, and pass the signal through the recon adapter. Read the configured timeout from settings and enforce the `60..21600` bounds.
- [ ] **Step 4: Run `pytest backend/tests/test_tool_execution_boundary_cancellation.py backend/tests/test_phase25_live_recon_validation.py -q`** and verify cancellation, timeout, argument allowlisting, and selected-port assertions pass.
- [ ] **Step 5: Commit** as `feat: support cancellable nmap execution`.

### Task 3: Discovery and Sequential Durable Worker

**Files:**
- Create: `backend/services/recon_live_run_worker.py`
- Modify: `backend/services/operator_live_recon_service.py`
- Modify: `backend/recon/live_recon_validator.py`
- Modify: `backend/main.py`
- Create: `backend/tests/test_recon_live_run_worker.py`

**Interfaces:**
- `ReconLiveRunWorker.discover(run_id: str) -> None` performs the existing passive/low-impact discovery phase, scope-checks each candidate, and persists unique authorized hosts plus provenance before setting `AWAITING_SCAN_CONFIRMATION`; it must not invoke Nmap.
- `ReconLiveRunWorker.confirm(run_id: str, operator_id: str, workload_confirmed: bool) -> dict` revalidates active authorization, scope hash, and exact full-port coverage, then atomically queues the run and wakes the runtime.
- `ReconLiveRunWorker.run_one_host(run_id: str) -> bool` claims and revalidates one host, runs through the existing adapter with one process at a time, saves execution/evidence identifiers and hashes, and returns whether work was consumed.
- `ReconLiveRunWorker.cancel(run_id: str) -> None` durably requests cancellation and signals the active host process; `ReconLiveRunRuntime.start/stop/trigger` integrates lifecycle/recovery without changing campaign completion semantics.
- Run-state terminal selection follows the spec: `COMPLETED` only if every queued host completes; otherwise use `PARTIAL`, `CANCELLED`, or `FAILED` with per-host detail.

- [ ] **Step 1: Write failing worker tests** for two-stage discovery/no Nmap, out-of-scope filtering, sequential host execution, restart recovery, cancellation between hosts, active-process cancellation, and honest partial completion.
- [ ] **Step 2: Run the focused tests and verify they fail** because the dedicated worker/runtime does not exist.
- [ ] **Step 3: Implement discovery/confirmation/worker runtime** using fresh DB sessions for background operations, persisted state transitions, a single worker slot, restart recovery for queued/running leases, and per-host execution via Task 2's cancellable boundary.
- [ ] **Step 4: Wire runtime startup and shutdown** in FastAPI lifespan after `init_db()` and before yielding; stop it cleanly before database/Redis teardown.
- [ ] **Step 5: Run `pytest backend/tests/test_recon_live_run_worker.py -q`** and verify all worker lifecycle and safety assertions pass.
- [ ] **Step 6: Commit** as `feat: run full-port recon in background`.

### Task 4: Run Lifecycle API and Access Control

**Files:**
- Modify: `backend/routers/campaigns.py`
- Modify: `backend/services/recon_live_run_repository.py`
- Create: `backend/tests/test_recon_live_run_api.py`

**Interfaces:**
- `POST /api/campaigns/{campaign_id}/recon-live-runs` validates campaign access, active authorization, and scope; creates a `DISCOVERING` run and returns HTTP 202 with `{run_id, state}`.
- `POST /api/campaigns/{campaign_id}/recon-live-runs/{run_id}/confirm` accepts `{workload_confirmed: true}` and queues only after revalidation.
- `GET /api/campaigns/{campaign_id}/recon-live-runs/{run_id}` returns run state, counts, current host, exact port plan, and host provenance/status/evidence summary.
- `POST /api/campaigns/{campaign_id}/recon-live-runs/{run_id}/cancel` requests cancellation and returns the durable state.
- Every endpoint verifies the run belongs to the path campaign and caller has campaign authorization; do not expose another campaign's run details.

- [ ] **Step 1: Write failing API tests** for 202 asynchronous start, no scan before confirmation, confirmation failure on incomplete ports/changed authorization, persisted status, cancellation, and cross-campaign/user denial.
- [ ] **Step 2: Run the focused tests and verify they fail** because the run routes are not registered.
- [ ] **Step 3: Implement request/response schemas and four routes** and connect them to Task 3 operations; keep existing inline passive/common-web endpoint behavior available.
- [ ] **Step 4: Run `pytest backend/tests/test_recon_live_run_api.py -q`** and verify response/state/access checks pass.
- [ ] **Step 5: Commit** as `feat: expose recon run lifecycle api`.

### Task 5: Two-Stage UI, Workload Review, Progress, and Cancellation

**Files:**
- Modify: `frontend/src/lib/api.js`
- Create: `frontend/src/components/ReconLiveRunPanel.jsx`
- Modify: `frontend/src/components/ReconToolExecutionPanel.jsx`
- Modify: `frontend/src/components/LiveReconPreflightModal.jsx`
- Create: `frontend/src/test/ReconLiveRunPanel.test.jsx`

**Interfaces:**
- API helpers `startReconLiveRun(campaignId)`, `confirmReconLiveRun(campaignId, runId, {workload_confirmed})`, `getReconLiveRun(campaignId, runId)`, and `cancelReconLiveRun(campaignId, runId)` use the four Task 4 routes.
- After discovery, display in-scope hosts and provenance, authorized/excluded/selected ports, selected-port count, and host × port workload; require a separate explicit checkbox/button to confirm.
- Poll status only while nonterminal; show each host's state and evidence link/hash, aggregate counts, partial/blocked details, and cancellation control; stop polling on terminal state/unmount.
- Full-port selection stays visibly blocked when saved authorization does not cover 1–65535; exclusions always show in effective range.

- [ ] **Step 1: Write failing component/API tests** for the discovery review barrier, exact workload display, authorization block, polling states, cancel request, terminal polling stop, and truthful partial outcome.
- [ ] **Step 2: Run `npm test -- --run src/test/ReconLiveRunPanel.test.jsx`** and verify it fails because the new flow is absent.
- [ ] **Step 3: Implement API helpers and panel** and connect it to the existing recon surface without removing the current common-web flow.
- [ ] **Step 4: Run `npm test -- --run src/test/ReconLiveRunPanel.test.jsx src/test/LiveReconPreflightModal.test.jsx src/test/ReconToolExecutionPanel.test.jsx`** and verify UI behavior passes.
- [ ] **Step 5: Commit** as `feat: add full-port recon run controls`.

### Task 6: End-to-End Contract Verification

**Files:**
- Create: `backend/tests/test_recon_live_run_flow.py`
- Modify only if required by failures: files from Tasks 1–5

**Interfaces:**
- Exercise the API, persistent repository, worker, scope gate, and mocked execution boundary as one flow; no external target or real Nmap invocation.

- [ ] **Step 1: Write a failing flow test** with a fake discovery source yielding in-scope, excluded, and duplicate hostnames; authorize ports 1–65535 with exclusions; assert discovery persists only authorized unique hosts and invokes no Nmap.
- [ ] **Step 2: Confirm the run in the test** and assert each unique host receives the exact compressed selected port set, one at a time, with saved output hash/evidence reference and truthful final status.
- [ ] **Step 3: Add failure/cancel variants** proving a timed-out/cancelled host yields a partial/cancelled run and later hosts do not start after cancellation.
- [ ] **Step 4: Run `pytest backend/tests/test_recon_live_run_flow.py -q`** and verify the complete offline contract passes.
- [ ] **Step 5: Run `git diff --check`, the focused backend suite, and the named frontend tests**; record exact results and any existing unrelated failures before declaring complete.
- [ ] **Step 6: Commit** as `test: verify full-port recon run lifecycle`.

## Self-Review

- **Spec coverage:** Durable models/migration/repository (Task 1); long-timeout boundary and process cancellation (Task 2); two-stage discovery, sequential worker, recovery, and progress (Task 3); start/confirm/status/cancel and campaign access (Task 4); workload review and UI status (Task 5); end-to-end range, exclusion, provenance, cancellation, and evidence contract (Task 6).
- **Step scan:** Each task has an explicit failing test, expected initial failure, bounded implementation, passing command, and commit. Task interfaces are defined before dependent tasks consume them.
- **Type consistency:** Repository persists `ReconLiveRun`/`ReconLiveRunHost`; worker methods consume `run_id`, `operator_id`, and boolean confirmation; API response uses `run_id/state`; frontend calls the same four routes.
- **Review focus:** All five uncovered failure classes above are pinned to repository, boundary, worker, API, or UI tests.
- **Proportion:** Six independently reviewable slices match the spec's cross-cutting persistent workflow; implementation detail stays at interfaces, tests, and required state behavior.
