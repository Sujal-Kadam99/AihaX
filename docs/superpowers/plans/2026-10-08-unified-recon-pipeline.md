# Unified Campaign Reconnaissance Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Use one authorized reconnaissance pipeline whenever AihaX performs recon in Safe Scan, Recon Only, Plan Only, or Fully Authorized mode.

**Architecture:** Campaign start creates one durable recon-run record before dependent work. The campaign worker claims recon runs on its existing background loop, invokes one campaign-facing provider pipeline with the saved authorization and scope, persists provider/asset/endpoint results separately from the immutable campaign authorization snapshot, and releases dependent checks only after successful recon. Recon Only creates no vulnerability-check tasks; Plan Only creates a plan without executing checks. Safe Scan and Fully Authorized modes use the same recon method and then follow their existing check policy. Nmap and Gobuster remain individually selected, scope-gated additions in every mode.

**Tech Stack:** Python 3, FastAPI, SQLAlchemy, SQLite migration runner, asyncio, React, Axios.

**Spec:** `docs/superpowers/specs/2026-10-08-unified-recon-pipeline-design.md`

## Global Constraints

- Every mode that performs recon invokes the same provider and inventory sequence with the same result/provenance contract.
- `RECON_ONLY` creates zero vulnerability-check tasks. `PLAN_ONLY` may produce an eligible-check plan but executes zero vulnerability checks.
- Safe Scan and Fully Authorized campaign check work is gated on the same shared recon run reaching `COMPLETED`.
- Mode affects active-tool permission and downstream checks, not recon-provider selection or discovery semantics.
- The active authorization and saved scope are revalidated immediately before network activity; out-of-scope rules override in-scope rules.
- Required passive providers are Subfinder, passive Amass, crt.sh, Wayback/GAU, DNS, and the built-in scoped wordlist; required HTTP inventory includes probing, technology/login-surface detection, and endpoint discovery.
- Nmap and Gobuster remain off unless individually selected; Nmap ports are the selected profile intersected with explicit `allowed_ports`, less `excluded_ports`.
- Sublist3r remains stub-only. Nuclei and Dalfox stay outside reconnaissance.
- Recon output describes observations and evidence; it never increments verified vulnerability findings.
- Recon results do not mutate the immutable campaign authorization/scope snapshot.

## Review Focus

- Campaign mode says `RECON_ONLY` while `start_campaign(auto_dispatch=True)` currently creates default vulnerability-check tasks; Task 3 must prove there are none and Task 4 must guard worker execution.
- Safe Scan, Plan Only, and Fully Authorized paths must call the same recon service and provider sequence; Task 2 pins mode parity and Tasks 3–4 pin dispatch order.
- Expired authorization or changed scope between campaign start and worker dispatch must block the run before any provider sends target traffic; Task 3 pins this behavior.
- A missing required tool/provider must produce a visible blocked status before target traffic, while a stub or vulnerability scanner must not be counted as recon; Task 4 pins this behavior.
- Empty `allowed_ports`, overlapping exclusions, and unauthorized selected active capabilities must block Nmap/Gobuster before process launch; Task 4 pins this behavior.
- Restart, duplicate dispatch, and provider failures must preserve one truthful durable run outcome and must not make the campaign complete early; Tasks 1–3 pin this behavior.

---

### Task 1: Durable Campaign Recon Run

**Files:**
- Modify: `backend/persistence/models.py`
- Modify: `backend/models/migrations.py`
- Modify: `backend/persistence/repository.py`
- Create: `backend/tests/test_campaign_recon_run_repository.py`

**Interfaces:**
- `CampaignReconRun`: `id`, `campaign_id` (unique), `campaign_mode`, `assessment_mode`, `state`, `authorization_id`, `scope_hash`, `selected_capabilities_json`, `result_json`, `failure_reason`, `worker_id`, `lease_expires_at`, `created_at`, `started_at`, `completed_at`.
- Repository operations: `create_recon_run(campaign_id, authorization_id, scope_hash, selected_capabilities)`, `claim_next_recon_run(worker_id, lease_seconds)`, `complete_recon_run(run_id, result_json)`, `fail_recon_run(run_id, reason)`, and `recover_stale_recon_runs()`.
- A recon run's lifecycle is `PENDING`, `RUNNING`, `COMPLETED`, `BLOCKED`, or `FAILED`; duplicate creation for one campaign is rejected/idempotent.

- [ ] **Step 1: Add repository tests** for unique campaign runs, persistence across sessions, atomic claim, stale-lease recovery, and terminal state persistence.
- [ ] **Step 2: Run the new repository tests and confirm the expected missing-model failures.**
- [ ] **Step 3: Add the ORM record, next migration, and repository operations** using existing migration checksum and claim conventions. Do not modify the untracked full-port recon draft.
- [ ] **Step 4: Run repository tests** and confirm unique, durable, recoverable run behavior.
- [ ] **Step 5: Commit** as `feat: persist campaign recon runs`.

### Task 2: Shared Recon Pipeline Across Modes

**Files:**
- Create: `backend/services/campaign_recon_service.py`
- Modify: `backend/recon/recon_preflight.py`
- Modify: `backend/recon/recon_orchestrator.py`
- Modify: `backend/recon/orchestrator.py`
- Modify: `backend/recon/providers.py`
- Modify: `backend/recon/endpoint_discovery.py` only if required by the unified adapter
- Modify: `backend/services/campaign_executor.py`
- Create: `backend/tests/test_campaign_recon_mode_parity.py`

**Interfaces:**
- `CampaignReconService.execute(run, campaign, db_session) -> dict` reloads active authorization and scope, builds one `ReconContext`, and returns a common JSON result with mode, provider statuses, scoped assets, endpoints, technologies, evidence hashes, and errors.
- `CampaignExecutor`'s RECON_ONLY and PLAN_ONLY branches and all worker campaign modes call this service instead of maintaining separate discovery implementations.
- Provider selection is the same ordered required set in every mode: `subfinder`, passive `amass`, `crtsh`, `wayback`, `gau`, `dns_recon`, `http_probe`, `whatweb`, `scoped_wordlist`, `endpoint_discovery`.
- Nmap/Gobuster are appended only by explicit selected capability, independent of mode; the same request engine and scope gates are used.

- [ ] **Step 1: Add mode-parity tests** proving the shared service invokes the same required provider sequence for Safe Scan, Recon Only, Plan Only, and Fully Authorized modes, while active-tool gating follows explicit authorization.
- [ ] **Step 2: Run the tests and verify current split orchestrators differ or are not called by the campaign worker.**
- [ ] **Step 3: Implement the shared campaign recon service** by composing existing providers and endpoint inventory without duplicating requests or bypassing the request engine.
- [ ] **Step 4: Route existing recon entry points through the shared service** and keep mode-specific behavior outside provider selection.
- [ ] **Step 5: Run mode-parity tests** and confirm identical provider ordering/result shape and mode-specific gates.
- [ ] **Step 6: Commit** as `feat: unify reconnaissance across campaign modes`.

### Task 3: Campaign Recon Scheduling and Worker Isolation

**Files:**
- Modify: `backend/services/campaign_operations.py`
- Modify: `backend/services/campaign_worker.py`
- Modify: `backend/routers/campaigns.py`
- Create: `backend/tests/test_recon_only_campaign_dispatch.py`

**Interfaces:**
- `CampaignOperationsService.start_campaign(..., auto_dispatch=True)` creates a pending `CampaignReconRun` for each campaign flow that performs recon, before creating dependent checks. `RECON_ONLY` and `PLAN_ONLY` create zero vulnerability `ExecutionTask` rows.
- `CampaignWorkerRuntime.dispatch_once()` claims and runs recon records before ordinary check work, using independent session-safe worker operations; no dependent check is claimable until recon succeeds.
- `CampaignWorker.execute_task()` has defense-in-depth guards that reject vulnerability check tasks for `RECON_ONLY` and `PLAN_ONLY` campaigns before any request or finding creation.
- Campaign completion waits for recon and any allowed downstream work, and remains idempotent across restart/re-dispatch.

- [ ] **Step 1: Add dispatch tests** proving all recon-enabled modes queue one recon record; Recon Only and Plan Only queue zero check IDs; dependent checks wait for recon; and a forged RECON_ONLY check task is blocked without invoking a check or request engine.
- [ ] **Step 2: Run those tests and verify the current default-check queue/worker path fails them.**
- [ ] **Step 3: Implement recon scheduling and worker dispatch** while preserving the existing mode-specific check policy after successful recon.
- [ ] **Step 4: Run dispatch tests** and confirm no vulnerability tasks execute and campaign completion follows recon state.
- [ ] **Step 5: Commit** as `fix: isolate recon-only campaign dispatch`.

### Task 4: Active Capability and Required-Tool Preflight

**Files:**
- Modify: `backend/routers/campaigns.py`
- Modify: `backend/services/campaign_operations.py`
- Modify: `backend/services/operator_live_recon_service.py`
- Modify: `backend/recon/live_recon_validator.py`
- Modify: `frontend/src/pages/NewAssessment.jsx`
- Modify: `frontend/src/components/LiveReconPreflightModal.jsx`
- Modify: `frontend/src/components/ReconToolExecutionPanel.jsx`
- Modify: `frontend/src/test/LiveReconPreflightModal.test.jsx`
- Modify: `backend/tests/test_operator_live_recon_workflow.py`

**Interfaces:**
- Campaign creation accepts `selected_capabilities: list[str]` restricted to `service_discovery` (Nmap) and `content_discovery` (Gobuster) and stores the choice in the immutable initial snapshot.
- Preflight checks all required providers before queueing; missing binary/provider or missing authorization blocks recon before target traffic and returns named status/reason.
- The live validation request schema accepts `port_scan_profile` (`web_common` or `all_authorized`) and preserves it through `payload.model_dump()` to the service.
- Nmap uses only effective explicit ports after exclusion. Gobuster uses the bundled wordlist and two workers. Neither runs unless selected.

- [ ] **Step 1: Add request/preflight tests** proving the selected profile survives request parsing, missing required providers block before traffic, Nmap exclusions are honored, and active capabilities default off.
- [ ] **Step 2: Run the focused tests and confirm the request field/preflight regressions fail.**
- [ ] **Step 3: Wire request/schema and UI selections** to the stored recon configuration and fail-closed preflight result.
- [ ] **Step 4: Run focused backend/frontend tests** and confirm selected/unselected capabilities and failure messaging.
- [ ] **Step 5: Commit** as `feat: gate campaign recon capabilities`.

### Task 5: Results, Progress, and Truthful Campaign State

**Files:**
- Modify: `backend/routers/campaigns.py`
- Modify: `backend/services/campaign_worker.py`
- Modify: `frontend/src/pages/Campaigns.jsx`
- Modify: `frontend/src/components/ReconToolExecutionPanel.jsx`
- Create: `frontend/src/components/CampaignReconRunPanel.jsx`
- Create: `backend/tests/test_campaign_recon_api.py`
- Create: `frontend/src/test/CampaignReconRunPanel.test.jsx`

**Interfaces:**
- `GET /api/campaigns/{campaign_id}/recon-run` returns durable state and stored result only for the path campaign.
- Campaign detail shows run state, per-provider result, host/endpoint/technology counts, evidence hashes, selected active capabilities and Nmap effective-port summary, plus explicit blocked/failed reasons.
- A recon run with unavailable required providers, authorization failure, or provider failure cannot be shown as clean complete; partial provider outputs remain visible.
- Verified-finding counts remain zero for RECON_ONLY and PLAN_ONLY because no vulnerability check task is run.
- Safe Scan and Fully Authorized results show the same recon run alongside downstream check outcomes.

- [ ] **Step 1: Add API/UI tests** for campaign-bound access, pending/running/terminal states, failed provider status, saved result display, and zero vulnerability-task/finding counts.
- [ ] **Step 2: Run the tests and verify missing status/result surfaces fail as expected.**
- [ ] **Step 3: Implement the status endpoint and campaign result panel** using the durable recon record.
- [ ] **Step 4: Run the focused backend/frontend tests** and confirm terminal status and error details render accurately.
- [ ] **Step 5: Commit** as `feat: show campaign recon results`.

### Task 6: Offline End-to-End Contract and Final Review

**Files:**
- Create: `backend/tests/test_recon_only_campaign_flow.py`
- Modify only as needed: files from Tasks 1–5

**Interfaces:**
- Exercise campaign creation/start, saved authorization, worker claim, provider pipeline, scope gate, durable result, and API read using mocked providers and a local transport.
- Assert zero vulnerability `ExecutionTask` rows, exact required provider set, no request to out-of-scope hosts, no Nmap/Gobuster unless selected, and truthful blocked/failed results.

- [ ] **Step 1: Write end-to-end contract tests** using in-scope, excluded, duplicate, and unavailable-provider fixtures.
- [ ] **Step 2: Run them to confirm the integrated path fails before completion.**
- [ ] **Step 3: Fix only integration defects uncovered by the flow.**
- [ ] **Step 4: Run focused backend/frontend verification, `git diff --check`, and inspect all resulting diffs without touching unrelated user changes.**
- [ ] **Step 5: Commit** as `test: verify recon-only campaign flow`.

## Self-Review

- **Spec coverage:** Tasks 1 and 3 cover durable dispatch, recovery, mode barriers, no vulnerability tasks in Recon Only/Plan Only, and honest completion; Task 2 covers one provider pipeline across all modes; Task 4 covers required-tool preflight and opt-in bounded Nmap/Gobuster; Task 5 covers persisted results and UI; Task 6 covers the complete offline contract.
- **Step scan:** Every task defines files, interfaces, a failing behavior, a minimal implementation step, and a verification command.
- **Type consistency:** `CampaignReconRun` is created and claimed through `CampaignRepository`, passed to `CampaignReconService.execute()`, and read from the matching campaign-level API route. Capability names and port profile values match frontend, request schemas, and service.
- **Review focus:** All five high-risk input classes map to explicit task tests above.
- **Proportion:** Six tasks follow the dependency order: persistence → shared pipeline → campaign lifecycle → preflight → result UI → offline contract.
