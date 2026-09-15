# AihaX — Full-System End-to-End GUI Demonstration & Integrity Audit Plan

**Document Version:** 1.0.0  
**Phase:** Demonstration & Integrity Audit (Phases 1–27 Complete, Phase 28 Out of Scope)  
**Security Classification:** Controlled Local Environment / Test Fixtures Only  
**Target Organization / Boundary:** `https://www.mitacsc.ac.in` / Pre-seeded Local Test Fixtures  

---

## 1. Executive Overview & Objectives

The primary objective of this audit is to demonstrate and prove, through the actual AihaX Graphical User Interface (GUI), that the entire platform functions end-to-end—from foundational runtime startup through Phase 27 reconnaissance tool provisioning and capability matrix enforcement.

This audit validates that every component is physically integrated in the live production code, accessible via the user interface, verified against the database and cryptographic audit trail, and rigorously protected by negative safety boundaries and default-deny policies.

### Strict Scope & Safety Boundaries
1. **Verification & Demonstration Only:** No Phase 28 functionality will be implemented or enabled.
2. **Zero Attack / Exploit Activity:** No live vulnerability testing, fuzzing, brute force, credential attacks, SQL injection, XSS exploitation, SSRF testing, directory fuzzing, Nuclei scanning, Dalfox scanning, or unrestricted port scanning.
3. **Local / Fixture Data First:** All demonstrations will utilize local database fixtures and controlled test responses (`db/aihax.db`, existing campaign records, pre-seeded evidence and findings). If controlled recon verification is demonstrated, it will strictly execute under existing `Authorization`, `ScopeValidator`, `ReconPreflightGate`, and `ToolExecutionBoundary` contracts.
4. **No Gate Bypasses:** No authorization, scope, or transport safety gates will be disabled or bypassed.

---

## 2. Environment & System Configuration Baseline

| Attribute | Value / Specification |
| :--- | :--- |
| **Operating System** | Windows (PowerShell Shell) |
| **Python Runtime** | Python 3.13.14 (`.venv\Scripts\python.exe`) |
| **Node.js Runtime** | Node.js v26.5.0, npm 12.0.2 |
| **Backend Startup Command** | `.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000` |
| **Frontend Startup Command** | `npm --prefix frontend run dev` (Vite dev server on `http://localhost:3000`) |
| **Database & Mode** | SQLite with WAL mode enabled (`db/aihax.db`) |
| **Database Migrations** | `backend/models/migrations.py` run at startup (`init_db`) |
| **Authentication Mode** | Local Desktop IPC token via `/api/auth/token` + Google OIDC Session |
| **Default Operator** | `lead_security_operator` (Role: Admin/Security Operator) |
| **Pre-seeded Fixture Campaign** | `bda03f2c-9c9d-4de2-a902-4a35c371eecc` (`Assessment: mitacsc.ac.in`, Status: `COMPLETED`) |
| **Pre-seeded Authorization Record** | `663e3722-931a-47ea-b932-4aba7d24dbe7` (Active, bound to `mitacsc.ac.in`) |
| **Pre-seeded Evidence Records** | 626 Cryptographically hashed records in `db/aihax.db` |
| **Pre-seeded Audit Events** | 4,875 Chained SHA-256 events in `db/aihax.db` |
| **Recon Tools Provisioned** | `bin/tools/subfinder.exe`, `amass.exe`, `gau.exe`, `whatweb.bat` / Ruby 3.3 runtime |

---

## 3. Architecture to GUI Route Mapping

The AihaX frontend is a desktop-first single-page application built on React 18, React Router v6, Tailwind CSS, Lucide Icons, and Axios with custom interceptors.

```
[ Frontend: React / Vite (Port 3000) ]
        │  (Axios Interceptor with X-AihaX-Token Header)
        ▼
[ Backend: FastAPI (Port 8000) ]
        ├── Auth Middleware: Desktop IPC Token / Google Session JWT
        ├── TrustedHostMiddleware: localhost, 127.0.0.1, ::1
        ├── CORS Middleware: http://localhost:3000, http://127.0.0.1:3000
        ├── Routers:
        │     ├── /api/auth       (Token retrieval, login, me, logout)
        │     ├── /api/health     (System health, DB status, Redis status)
        │     ├── /api/programs   (Bug bounty programs, in/out scope, scope validator)
        │     ├── /api/campaigns  (Lifecycle: draft, authorize, start, pause, resume, cancel)
        │     ├── /api/findings   (Finding details, quality gates, human review)
        │     ├── /api/reports    (PDF generation, report manifest download)
        │     ├── /campaigns/{id} (Evidence, timeline, execution summary, integrity)
        │     └── /ws/{scan_id}   (Live execution streaming)
        └── Persistence Engine:
              ├── SQLite WAL DB (`db/aihax.db`)
              ├── Audit Trail Hash Chaining (SHA-256 genesis-to-tip)
              └── ToolExecutionBoundary (`bin/tools/*`)
```

### Complete GUI Routes & API Mapping Table

| Page / Component | Route | Key Backend APIs | Primary Purpose |
| :--- | :--- | :--- | :--- |
| **Dashboard** | `/` | `GET /api/health`<br>`GET /api/campaigns?limit=5`<br>`GET /api/campaigns/metrics/operational` | System readiness, active campaigns, task count, verified findings count |
| **Targets & Programs** | `/targets` | `GET /api/programs`<br>`POST /api/programs`<br>`POST /api/programs/{id}/validate-target` | Program scope definition (in-scope/out-of-scope), live zero-network scope evaluator |
| **New Assessment** | `/new-assessment` | `GET /api/programs`<br>`POST /api/programs/{id}/validate-target`<br>`POST /api/campaigns`<br>`POST /api/campaigns/{id}/authorize`<br>`POST /api/campaigns/{id}/start` | 4-step wizard: Target URL, Scope validation, Operator authorization, Pre-flight readiness gate, Campaign dispatch |
| **Campaigns Console** | `/campaigns`<br>`/campaigns?id={id}` | `GET /api/campaigns`<br>`GET /api/campaigns/{id}`<br>`GET /api/campaigns/{id}/runtime`<br>`POST /api/campaigns/{id}/start|pause|resume|cancel`<br>`GET /api/campaigns/{id}/integrity` | Operational campaign management, worker task leases, state transitions, integrity verification |
| **Recon Tools Panel** | `/campaigns?id={id}` *(View: Recon Tools)* | Embedded Component `ReconToolExecutionPanel`<br>`GET /api/campaigns/{id}/runtime` | Truthful 13-tool capability matrix, execution results, normalization status, evidence hashes |
| **Attack Surface Graph** | `/campaigns?id={id}` *(View: Attack Surface)* | `GET /api/campaigns/{id}/attack-surface` | Graph visualization of discovered assets, services, and endpoints (`DISCOVERED_NOT_AUTHORIZED`) |
| **Evidence Vault** | `/evidence`<br>`/evidence?campaign={id}` | `GET /api/campaigns/{id}/evidence`<br>`GET /api/campaigns/{id}/execution-summary` | Cryptographic evidence records, SHA-256 hashes, pre-storage secret redaction, payload inspection |
| **Findings Intelligence** | `/findings` | `GET /api/findings/all`<br>`GET /api/campaigns/{id}/findings` | Verified findings catalog with filters: VALIDATED, HARDENING_ONLY, INCONCLUSIVE, FALSE_POSITIVE, NOT_BOUNTY_ELIGIBLE |
| **Finding Detail** | `/findings/:id` | `GET /api/findings/detail/{id}`<br>`POST /api/findings/{id}/review` | Detailed proof of concept, multi-dimensional confidence breakdown, machine explanation, human operator review gate |
| **Reports Catalog** | `/reports` | `GET /api/campaigns`<br>`POST /api/campaigns/{id}/reports`<br>`GET /api/campaigns/{id}/reports/download` | Audit-grade report generation, PDF download, cryptographic integrity anchoring |
| **Audit Trail** | `/audit`<br>`/audit?campaign={id}` | `GET /api/campaigns/{id}/audit` | Genesis-to-tip SHA-256 chained audit logs, operator tracking, non-repudiation |
| **Settings Console** | `/settings` | `GET /api/settings`<br>`POST /api/settings`<br>`GET /api/auth/me` | Operator profile, role, concurrency, rate limit presets, storage configuration |

---

## 4. End-to-End GUI Demonstration Test Specifications

The following 22 verification test cases constitute the formal audit battery to be executed against the live application.

---

### Test Case TC-01: Application Startup & Backend Connectivity
* **Component:** Health Service & App Shell Layout
* **Expected Behavior:** Backend starts on port 8000, Vite dev server starts on port 3000. Frontend successfully queries `/api/health` and displays green "System Ready" badge.
* **GUI Route / Page:** Top navigation bar on all pages (`/`)
* **Backend API Dependency:** `GET http://localhost:8000/api/health`
* **Test Data / Fixture Required:** Active SQLite database (`db/aihax.db`)
* **Expected Visual Result:**
  * Top bar status pill displays green pulsing dot: `System Ready` (or `Ready (Redis Optional)`).
  * Operator badge displays `Operator: Admin` with `AUTHD` tag.
  * Theme toggle switch (Dark/Light) functions cleanly.
* **Expected Backend Result:** HTTP 200 returned with JSON payload `{"status":"ok","version":"1.0.0","redis":"ok","database":"ok"}`.
* **Evidence Required:** Browser screenshot of header bar, DevTools network request for `/api/health`.
* **Pass / Fail Criteria:** PASS if status is green and no network error occurs; FAIL if "Backend Disconnected" is shown.

---

### Test Case TC-02: Local Authentication & Desktop IPC Token Retrieval
* **Component:** Authentication Middleware (`lib/api.js` & `backend/routers/auth.py`)
* **Expected Behavior:** The frontend Axios client interceptor calls `GET /api/auth/token` on startup, caches the local desktop token, and attaches `X-AihaX-Token` to all subsequent API requests.
* **GUI Route / Page:** `/` and `/settings`
* **Backend API Dependency:** `GET /api/auth/token`, `GET /api/auth/me`
* **Test Data / Fixture Required:** Local request origin (`http://localhost:3000` to `127.0.0.1:8000`)
* **Expected Visual Result:** Application routes load smoothly without 401 Unauthorized modals or login redirects. Settings page displays authenticated operator profile (`lead_security_operator`).
* **Expected Backend Result:** `/api/auth/token` returns `{"token": "<desktop_token>"}` with status 200. All subsequent API endpoints validate the token.
* **Evidence Required:** Browser console and network headers showing `X-AihaX-Token: [REDACTED_TOKEN]`.
* **Pass / Fail Criteria:** PASS if all authenticated APIs return 200 without auth rejection; FAIL if 401/403 occurs.

---

### Test Case TC-03: Security Operations Dashboard
* **Component:** Dashboard Overview (`pages/Dashboard.jsx`)
* **Expected Behavior:** Real-time metrics aggregated across campaigns, tasks, findings, and reports are rendered correctly.
* **GUI Route / Page:** `/`
* **Backend API Dependency:**
  * `GET /api/campaigns?limit=5`
  * `GET /api/health`
  * `GET /api/campaigns/metrics/operational`
* **Test Data / Fixture Required:** Seeded campaigns and findings in `db/aihax.db`
* **Expected Visual Result:**
  * 4 Metric cards: Active Campaigns, Running Tasks, Verified Findings, Reports & Manifests.
  * "Recent Security Campaigns" table listing at least `Assessment: mitacsc.ac.in` (`COMPLETED`) and other campaigns.
  * Safety & Verification Controls checklist showing green checkmarks for:
    * Scope Enforcement (Default-Deny Active)
    * Pre-Flight Transport Gate (Zero-Byte Guard)
    * Evidence Redaction Engine (9 Regex Filters)
    * Audit Trail Hash Chaining (SHA-256 Chained)
    * Database Storage (SQLite WAL Active)
* **Expected Backend Result:** HTTP 200 on all 3 dashboard API endpoints.
* **Evidence Required:** Browser screenshot of Dashboard page.
* **Pass / Fail Criteria:** PASS if all metric cards display real integers and recent campaigns render; FAIL if cards display error or blank.

---

### Test Case TC-04: Target Program Scope & Asset Boundaries
* **Component:** Program Management (`pages/Targets.jsx`)
* **Expected Behavior:** Lists all authorized target programs, displays in-scope assets (`https://mitacsc.ac.in/*`), out-of-scope assets, allowed/excluded ports, and active campaigns assigned.
* **GUI Route / Page:** `/targets`
* **Backend API Dependency:** `GET /api/programs`
* **Test Data / Fixture Required:** Seeded programs (e.g. `mit`, `HackerOne`, `Eternal`)
* **Expected Visual Result:**
  * Left column lists authorized programs with badge `AUTHORIZED`.
  * Selecting `mit` displays program scope summary card:
    * In-Scope Assets: `https://www.mitacsc.ac.in/*`, `*.mitacsc.ac.in`
    * Out-of-Scope Assets: explicit exclusion rules
    * Allowed Ports: `80, 443`
    * Excluded Ports: `22, 25, 3389`
  * Campaign Assignments card displays assigned campaigns (`Assessment: mitacsc.ac.in`) with status `COMPLETED` and `RELEASED (Completed)`.
* **Expected Backend Result:** `GET /api/programs` returns 200 with list of programs and nested scope definitions.
* **Evidence Required:** Browser screenshot of Targets page with program selected.
* **Pass / Fail Criteria:** PASS if scope rules, ports, and campaign assignments render accurately; FAIL if list is empty or broken.

---

### Test Case TC-05: Positive Scope Pre-Flight Evaluation (Safe Action)
* **Component:** Interactive Scope Validator (`pages/Targets.jsx`)
* **Expected Behavior:** Operator inputs an in-scope target URL (`https://www.mitacsc.ac.in/about-us`), clicks "Evaluate Scope", and backend returns deterministic `IN_SCOPE` approval with zero network traffic dispatched.
* **GUI Route / Page:** `/targets` (Scope Pre-Flight Evaluation form)
* **Backend API Dependency:** `POST /api/programs/{id}/validate-target` with payload `{"target":"https://www.mitacsc.ac.in/about-us","port":443}`
* **Test Data / Fixture Required:** Program `mit` selected
* **Expected Visual Result:**
  * Green scope validation banner appears:
    * `● SCOPE VALIDATED`
    * Status: `IN_SCOPE` &bull; Reason: `Matched in-scope asset rule https://www.mitacsc.ac.in/*`
* **Expected Backend Result:** HTTP 200 with `{"allowed": true, "status": "IN_SCOPE", "reason": "..."}`. Zero external network socket calls.
* **Evidence Required:** Browser screenshot of positive scope validation banner, DevTools network response.
* **Pass / Fail Criteria:** PASS if allowed is true and green banner displays; FAIL if blocked or errored.

---

### Test Case TC-06: Negative Scope Pre-Flight Evaluation (Out-of-Scope Target Rejection)
* **Component:** Interactive Scope Validator (`pages/Targets.jsx`)
* **Expected Behavior:** Operator inputs an unauthorized target URL (`https://evil-unauthorized-target.com`), clicks "Evaluate Scope", and backend firmly rejects it with `OUT_OF_SCOPE` status.
* **GUI Route / Page:** `/targets` (Scope Pre-Flight Evaluation form)
* **Backend API Dependency:** `POST /api/programs/{id}/validate-target` with payload `{"target":"https://evil-unauthorized-target.com","port":443}`
* **Test Data / Fixture Required:** Program `mit` selected
* **Expected Visual Result:**
  * Red scope rejection banner appears:
    * `● OUT OF SCOPE — BLOCKED`
    * Status: `OUT_OF_SCOPE` &bull; Reason: `Target does not match any allowed in-scope pattern.`
    * Warning: `Safety Invariant: Requests to this target will be terminated before any network transmission.`
* **Expected Backend Result:** HTTP 200 with `{"allowed": false, "status": "OUT_OF_SCOPE"}`. Zero network bytes.
* **Evidence Required:** Browser screenshot of negative scope rejection banner.
* **Pass / Fail Criteria:** PASS if rejected with `OUT_OF_SCOPE` and zero network requests made; FAIL if permitted.

---

### Test Case TC-07: New Assessment Wizard — Concrete Target URL Enforcement
* **Component:** Assessment Configuration (`pages/NewAssessment.jsx`)
* **Expected Behavior:** Wildcard URLs (e.g. `*.mitacsc.ac.in`) are rejected with `WILDCARD_TARGET_NOT_ALLOWED`. Only concrete HTTP/HTTPS URLs (e.g. `https://www.mitacsc.ac.in`) are accepted.
* **GUI Route / Page:** `/new-assessment`
* **Backend API Dependency:** `POST /api/programs/{id}/validate-target`
* **Test Data / Fixture Required:** Input test strings `*.mitacsc.ac.in` vs `https://www.mitacsc.ac.in`
* **Expected Visual Result:**
  * Entering `*.mitacsc.ac.in` and clicking "Validate Scope" displays error:
    * `● INVALID TARGET: Wildcard targets are not allowed. Enter a concrete HTTP/HTTPS target URL.`
  * Step 2 (Authorization) and Step 3 (Configuration) remain locked and disabled (`opacity-50 pointer-events-none`).
  * "Launch Assessment" button remains disabled with warning: `Scope validation required before launch.`
* **Expected Backend Result:** Frontend validator flags error; backend rejects wildcard target if submitted.
* **Evidence Required:** Browser screenshot of wildcard rejection banner.
* **Pass / Fail Criteria:** PASS if wildcard is blocked; FAIL if wildcard can be submitted.

---

### Test Case TC-08: Pre-Flight Readiness Gate & Transport Boundary Check
* **Component:** Pre-Flight Readiness Card (`pages/NewAssessment.jsx`)
* **Expected Behavior:** Entering `https://www.mitacsc.ac.in` and selecting authorized program validates successfully. Step 4 "PRE-FLIGHT READINESS" checklist unlocks, verifying all 9 deterministic invariants.
* **GUI Route / Page:** `/new-assessment`
* **Backend API Dependency:** `POST /api/programs/{id}/validate-target`
* **Test Data / Fixture Required:** Valid concrete target `https://www.mitacsc.ac.in`
* **Expected Visual Result:**
  * Step 1 Scope Banner: `● SCOPE VALIDATED`
  * Step 4 Checklist renders 9 verification cards with green checkmarks:
    1. Target URL: `https://www.mitacsc.ac.in`
    2. Program & Policy: `mit`
    3. Scope Decision: `IN SCOPE (PASS)`
    4. Authorization: `PASS (30d Active)`
    5. Destination Safety: `PASS (Metadata / SSRF Blocked)`
    6. Request Budget / Limit: `500 Max Requests`
    7. Concurrency & Rate: `5 Workers`
    8. Allowed HTTP Methods: `Standard Methods`
    9. RequestEngine Boundary: `REQUIRED (Central Transport)`
  * Launch button activates: `Launch Controlled Assessment`
* **Expected Backend Result:** Pre-flight parameters pass validation.
* **Evidence Required:** Browser screenshot of complete Pre-Flight Readiness Checklist.
* **Pass / Fail Criteria:** PASS if all 9 checklist items pass and launch button enables; FAIL if any check fails or is bypassed.

---

### Test Case TC-09: Production Mode Conservative Rate & Budget Gating
* **Component:** Mode Switcher (`pages/NewAssessment.jsx`)
* **Expected Behavior:** Switching Assessment Mode from `CONTROLLED` to `PRODUCTION_AUTHORIZED` locks server-enforced limits (Budget: 10 requests, Concurrency: 1 worker, Rate: 2 RPS, Methods: GET/HEAD/OPTIONS only) and requires explicit operator checkbox confirmation.
* **GUI Route / Page:** `/new-assessment`
* **Backend API Dependency:** `createCampaign` with `assessment_mode="PRODUCTION_AUTHORIZED"`
* **Test Data / Fixture Required:** Assessment mode dropdown set to `PRODUCTION_AUTHORIZED`
* **Expected Visual Result:**
  * Amber banner appears: `CONSERVATIVE PRODUCTION PROFILE (LOCKED BY SERVER)`.
  * Budget locked to `10 Max Requests`, Concurrency `1 Worker`, Rate `2 RPS`.
  * Checkbox appears: *"I confirm this concrete target is authorized under the selected bug-bounty program..."*
  * Launch button is disabled until checkbox is checked.
* **Expected Backend Result:** Server enforces max budget 10 and max concurrency 1.
* **Evidence Required:** Browser screenshot of locked production profile and confirmation checkbox.
* **Pass / Fail Criteria:** PASS if limits are locked and operator confirmation is required; FAIL if custom large budgets can be entered.

---

### Test Case TC-10: Existing Campaign Operations Console & State Inspection
* **Component:** Campaign Operations (`pages/Campaigns.jsx`)
* **Expected Behavior:** Operator selects the certified assessment campaign `Assessment: mitacsc.ac.in` (`bda03f2c-9c9d-4de2-a902-4a35c371eecc`). The console renders full runtime truth: state `COMPLETED`, requests used, task summary, evidence count, and verified findings.
* **GUI Route / Page:** `/campaigns?id=bda03f2c-9c9d-4de2-a902-4a35c371eecc`
* **Backend API Dependency:**
  * `GET /api/campaigns`
  * `GET /api/campaigns/bda03f2c-9c9d-4de2-a902-4a35c371eecc`
  * `GET /api/campaigns/bda03f2c-9c9d-4de2-a902-4a35c371eecc/runtime`
  * `GET /api/campaigns/bda03f2c-9c9d-4de2-a902-4a35c371eecc/evidence`
  * `GET /api/campaigns/bda03f2c-9c9d-4de2-a902-4a35c371eecc/findings`
* **Test Data / Fixture Required:** Campaign `bda03f2c-9c9d-4de2-a902-4a35c371eecc` in `db/aihax.db`
* **Expected Visual Result:**
  * Campaign Name: `Assessment: mitacsc.ac.in` with badge `COMPLETED`.
  * Target URL: `https://mitacsc.ac.in`.
  * Runtime State panel:
    * Backend State: `CONNECTED` (or `DEGRADED (Redis Optional)`)
    * Current Phase: `COMPLETED`
    * Active Operation: `Assessment completed`
    * Evidence / Findings stats displayed accurately.
  * Control buttons available: `Verify Integrity`.
* **Expected Backend Result:** All endpoints return 200 with structured JSON data.
* **Evidence Required:** Browser screenshot of Campaigns console in Overview mode.
* **Pass / Fail Criteria:** PASS if campaign detail loads and matches backend DB record; FAIL if 404 or blank screen.

---

### Test Case TC-11: Cryptographic Campaign Integrity Verification (Safe Action)
* **Component:** Campaign Integrity Engine (`pages/Campaigns.jsx`)
* **Expected Behavior:** Operator clicks "Verify Integrity" button. The backend computes SHA-256 hashes across evidence records, audit trail chain, and campaign snapshot, returning 100% mathematical integrity verification.
* **GUI Route / Page:** `/campaigns?id=bda03f2c-9c9d-4de2-a902-4a35c371eecc`
* **Backend API Dependency:** `GET /api/campaigns/bda03f2c-9c9d-4de2-a902-4a35c371eecc/integrity`
* **Test Data / Fixture Required:** Campaign `bda03f2c-9c9d-4de2-a902-4a35c371eecc`
* **Expected Visual Result:**
  * Toast notification appears: `Integrity Verified: Evidence, audit chain, and snapshot verified 100%.`
* **Expected Backend Result:** HTTP 200 with `{"verified": true, "issues": [], "evidence_integrity": "OK", "audit_chain_integrity": "OK"}`.
* **Evidence Required:** Browser screenshot of toast notification, DevTools response for `/integrity`.
* **Pass / Fail Criteria:** PASS if verified is true; FAIL if integrity violations are flagged.

---

### Test Case TC-12: Recon UI & Truthful 13-Tool Capability Matrix
* **Component:** Recon Tool Execution Panel (`components/ReconToolExecutionPanel.jsx` via `/campaigns`)
* **Expected Behavior:** Opening "Recon Tools (Phase 25)" tab renders the complete, truthful capability matrix across all 13 tools. No tool status is fabricated.
* **GUI Route / Page:** `/campaigns?id=bda03f2c-9c9d-4de2-a902-4a35c371eecc` (Tab: *Recon Tools (Phase 25)*)
* **Backend API Dependency:** Embedded component / runtime tool records
* **Test Data / Fixture Required:** Phase 25/26/27 tool capability records
* **Expected Visual Result:**
  * Table renders 13 rows with truthful statuses:
    1. `subfinder`: `LIVE_VALIDATED` (or installed/validated)
    2. `amass`: `LIVE_VALIDATED`
    3. `gau`: `LIVE_VALIDATED`
    4. `whatweb`: `LIVE_VALIDATED`
    5. `dns_recon`: `LIVE_VALIDATED`
    6. `http_probe`: `LIVE_VALIDATED`
    7. `crtsh`: `LIVE_VALIDATED` / Native Provider
    8. `wayback`: `LIVE_VALIDATED` / Native Provider
    9. `nmap`: `BLOCKED_POLICY` (*Port scanning is not explicitly authorized under program policy*)
    10. `gobuster`: `BLOCKED_POLICY` (*Directory brute force is not explicitly authorized under program policy*)
    11. `nuclei`: `NOT_SELECTED_RECON_ONLY` (*Vulnerability scanner; excluded from recon-only validation*)
    12. `dalfox`: `NOT_SELECTED_RECON_ONLY` (*Active XSS scanner/fuzzer; excluded from recon-only validation*)
    13. `sublist3r`: `STUB_ONLY` (*PRODUCTION_CAPABILITY_NOT_IMPLEMENTED*)
  * Filter pills (`ALL`, `EXECUTED`, `BLOCKED`, `FAILED`) filter table rows dynamically.
* **Expected Backend Result:** Statuses truthfully represent the exact capability matrix established through Phase 27.
* **Evidence Required:** Browser screenshot of Recon Tools capability matrix table.
* **Pass / Fail Criteria:** PASS if all 13 tools reflect their truthful status and blocked tools are explicitly marked `BLOCKED_POLICY` / `NOT_SELECTED_RECON_ONLY` / `STUB_ONLY`; FAIL if any blocked tool is marked active.

---

### Test Case TC-13: Recon Tool Inspection Drawer & Audit Lifecycle Timeline
* **Component:** Tool Execution Detail (`components/ReconToolExecutionPanel.jsx`)
* **Expected Behavior:** Clicking any tool row (e.g. `nmap` or `subfinder`) expands the detail drawer showing Execution ID, Phase 26 Validation Matrix (Installed, Adapter, Selected, Authorization, Execution, Output, Parsing, Normalization, Evidence, Snapshot, Graph, Live Validation), and Failure / Rationale reason.
* **GUI Route / Page:** `/campaigns?id=bda03f2c-9c9d-4de2-a902-4a35c371eecc` (Expanded tool row)
* **Test Data / Fixture Required:** Tool records
* **Expected Visual Result:**
  * For `nmap`: Authorization displays `POLICY_GATED`, Execution displays `NO`, Rationale displays *"Port scanning is not explicitly authorized under program policy."*
  * For `sublist3r`: Status displays `STUB_ONLY`, Rationale displays *"STUB_ONLY / PRODUCTION_CAPABILITY_NOT_IMPLEMENTED"*.
* **Evidence Required:** Browser screenshot of expanded tool drawer.
* **Pass / Fail Criteria:** PASS if drawer expands and displays truthful lifecycle rationale; FAIL if empty.

---

### Test Case TC-14: Attack Surface Graph & Asset Scope Invariants
* **Component:** Attack Surface Graph (`components/AttackSurfaceGraph.jsx` via `/campaigns`)
* **Expected Behavior:** Opening "Attack Surface (Phase 23)" tab renders discovered assets, hostnames, ports, and endpoints. Discovered assets are explicitly tagged `DISCOVERED_NOT_AUTHORIZED` with `is_executable = false`.
* **GUI Route / Page:** `/campaigns?id=bda03f2c-9c9d-4de2-a902-4a35c371eecc` (Tab: *Attack Surface (Phase 23)*)
* **Backend API Dependency:** `GET /api/campaigns/{id}/attack-surface`
* **Test Data / Fixture Required:** Campaign `bda03f2c-9c9d-4de2-a902-4a35c371eecc`
* **Expected Visual Result:**
  * Attack surface inventory / graph renders discovered nodes.
  * Node detail displays status badge `DISCOVERED_NOT_AUTHORIZED`.
  * Safety note: Discovered assets cannot be targeted without separate explicit authorization.
* **Expected Backend Result:** HTTP 200 returning attack surface nodes and edges with `is_executable=false`.
* **Evidence Required:** Browser screenshot of Attack Surface Graph view.
* **Pass / Fail Criteria:** PASS if discovered nodes remain `DISCOVERED_NOT_AUTHORIZED`; FAIL if executable without authorization.

---

### Test Case TC-15: Cryptographic Evidence Vault & Secret Redaction Verification
* **Component:** Evidence Management (`pages/Evidence.jsx`)
* **Expected Behavior:** Operator navigates to `/evidence`. Campaign evidence artifacts are rendered with SHA-256 content hashes, method, target URL, and verified integrity. Inspecting an artifact verifies that passwords, authorization tokens, cookies, and secrets are redacted before persistence.
* **GUI Route / Page:** `/evidence?campaign=bda03f2c-9c9d-4de2-a902-4a35c371eecc`
* **Backend API Dependency:**
  * `GET /api/campaigns/bda03f2c-9c9d-4de2-a902-4a35c371eecc/evidence`
  * `GET /api/campaigns/bda03f2c-9c9d-4de2-a902-4a35c371eecc/execution-summary`
* **Test Data / Fixture Required:** Pre-seeded evidence records in `db/aihax.db`
* **Expected Visual Result:**
  * Evidence artifacts table renders rows with Evidence ID, Type (`CHECK_EXECUTION_EVIDENCE`, `PROOF`, etc.), Target URL, SHA-256 Hash (`3f8a...`), and Integrity Status (`Verified`).
  * Clicking "Inspect" opens the Evidence Detail Modal:
    * Metadata Grid: Method, HTTP Status (`200 OK`), Target URL, Finding ID.
    * Green Banner: `Secrets, auth tokens, passwords, and cookies are cryptographically redacted. REDACTED`.
    * SHA-256 Content Hash (full hex string).
    * Sanitized Request & Response payloads displayed safely.
* **Expected Backend Result:** HTTP 200 with evidence records containing zero plaintext credentials.
* **Evidence Required:** Browser screenshot of Evidence table and Evidence Detail Modal.
* **Pass / Fail Criteria:** PASS if SHA-256 hashes match and secrets are redacted; FAIL if plaintext credentials are displayed.

---

### Test Case TC-16: Execution Timeline & Evidence Visibility Gate
* **Component:** Execution Timeline (`components/ExecutionTimeline.jsx` via `/evidence`)
* **Expected Behavior:** Switching to "Execution Timeline" tab renders the chronological order of execution events (started, completed, blocked, evidence captured). The UI strictly distinguishes between execution states and never claims SUCCESS if a check was blocked or failed.
* **GUI Route / Page:** `/evidence` (Tab: *Execution Timeline*)
* **Backend API Dependency:** `GET /api/campaigns/{id}/timeline`
* **Test Data / Fixture Required:** Pre-seeded timeline events
* **Expected Visual Result:**
  * Vertical timeline with event badges, timestamps, duration, and direct links to evidence artifacts.
* **Expected Backend Result:** HTTP 200 returning timeline events.
* **Evidence Required:** Browser screenshot of Execution Timeline view.
* **Pass / Fail Criteria:** PASS if timeline matches backend events; FAIL if status contradicts backend state.

---

### Test Case TC-17: Findings Intelligence Catalog & Disposition Filtering
* **Component:** Findings Management (`pages/Findings.jsx`)
* **Expected Behavior:** Operator navigates to `/findings`. Findings list is rendered with severity badges, titles, target URLs, verification state, and confidence scores. Quick filter dropdown demonstrates the full finding lifecycle:
  * `VALIDATED` (Vulnerability)
  * `HARDENING_ONLY`
  * `INCONCLUSIVE`
  * `FALSE_POSITIVE`
  * `NOT_BOUNTY_ELIGIBLE`
  * `CANDIDATE` (Unverified)
* **GUI Route / Page:** `/findings`
* **Backend API Dependency:** `GET /api/campaigns/{id}/findings` or `GET /api/findings/all`
* **Test Data / Fixture Required:** Seeded findings in `db/aihax.db`
* **Expected Visual Result:**
  * Table renders findings with color-coded severity pills (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
  * Verification State badges accurately display machine disposition (`VALIDATED`, `HARDENING_ONLY`, `INCONCLUSIVE`, `FALSE_POSITIVE`, `CANDIDATE`).
  * Filtering by status filters the table cleanly without React crashes.
* **Expected Backend Result:** HTTP 200 with finding records.
* **Evidence Required:** Browser screenshot of Findings table with diverse dispositions shown.
* **Pass / Fail Criteria:** PASS if all dispositions are represented and filters work; FAIL if dispositions are collapsed or missing.

---

### Test Case TC-18: Finding Detail & Automated Verification Quality Gate
* **Component:** Finding Detail (`pages/FindingDetail.jsx`)
* **Expected Behavior:** Clicking a finding opens `/findings/:id`. The page demonstrates the complete finding quality and verification model:
  1. Factual Observed Impact vs Theoretical Potential Impact (`[INFERENCE]`).
  2. Cryptographic Proof of Concept (Request & Response).
  3. "Automated Finding Verification & Quality Gate" Card:
     * Machine Disposition badge (`VALIDATED` / `INCONCLUSIVE` / `HARDENING_ONLY`).
     * Bounty Scope badge (`ELIGIBLE` / `INELIGIBLE`).
     * Machine Reason Explanation ("Why AihaX Reached This Disposition").
     * Multi-Dimensional Confidence Breakdown:
       * Condition Confidence
       * Impact Confidence
       * Reproducibility Confidence
       * Exploitability Confidence
       * Policy Eligibility Confidence
     * Deterministic Verification Checklist items.
* **GUI Route / Page:** `/findings/:id`
* **Backend API Dependency:** `GET /api/findings/detail/{id}`
* **Test Data / Fixture Required:** Pre-seeded finding record in `db/aihax.db`
* **Expected Visual Result:** All cards render with exact confidence percentages and checklist items.
* **Expected Backend Result:** HTTP 200 returning full finding record with `verification_explanation` JSON.
* **Evidence Required:** Browser screenshot of Finding Detail page showing the Automated Verification Gate card.
* **Pass / Fail Criteria:** PASS if multi-dimensional confidence breakdown and machine explanation render; FAIL if missing.

---

### Test Case TC-19: Human Operator Review Gate (Safe GUI Action)
* **Component:** Operator Review Gate (`pages/FindingDetail.jsx`)
* **Expected Behavior:** Operator inputs review notes (e.g. *"Verified during GUI audit demonstration"*) and clicks "Approve for Report" (or "Reject / False Positive"). The UI updates immediately to `Review Status: APPROVED` with operator attribution.
* **GUI Route / Page:** `/findings/:id` (Operator Review Gate panel)
* **Backend API Dependency:** `POST /api/findings/{id}/review` with payload `{"decision":"APPROVE","notes":"Verified during GUI audit demonstration","actor":"operator"}`
* **Test Data / Fixture Required:** Verified finding record
* **Expected Visual Result:**
  * Success message: `Finding APPROVEDed successfully.`
  * Badge updates to `Review Status: APPROVED`.
  * Attribution appears: `Reviewed by: operator at [Timestamp]`.
* **Expected Backend Result:** Database updated with `human_review_status='APPROVED'`, `human_reviewed_by='operator'`.
* **Evidence Required:** Browser screenshot after clicking Approve, DevTools POST `/review` response.
* **Pass / Fail Criteria:** PASS if review state updates in UI and database; FAIL if review action fails.

---

### Test Case TC-20: Security Reports Generation & Artifact Verification
* **Component:** Reports Catalog (`pages/Reports.jsx`)
* **Expected Behavior:** Operator navigates to `/reports`. Clicking "Generate" for a completed campaign triggers report manifest compilation. Clicking "Download PDF" retrieves the generated report artifact and verifies the PDF header magic bytes (`%PDF-`).
* **GUI Route / Page:** `/reports`
* **Backend API Dependency:**
  * `GET /api/campaigns`
  * `POST /api/campaigns/{id}/reports`
  * `GET /api/campaigns/{id}/reports/download` (responseType: `blob`)
* **Test Data / Fixture Required:** Campaign `bda03f2c-9c9d-4de2-a902-4a35c371eecc`
* **Expected Visual Result:**
  * Reports table lists campaigns with status `COMPLETED` and `ShieldCheck Verified` integrity anchor.
  * Clicking "Generate" produces toast: `Report Manifest Ready: Generated bug bounty report summary...`
  * Clicking "Download PDF" downloads `AihaX-Assessment__mitacsc_ac_in-bda03f2c.pdf` without error.
* **Expected Backend Result:** `POST /reports` returns 200; `GET /download` streams valid PDF bytes (`%PDF-1.4...`).
* **Evidence Required:** Browser screenshot of Reports catalog, downloaded PDF file metadata.
* **Pass / Fail Criteria:** PASS if report generates and valid PDF downloads; FAIL if 500 error or empty file.

---

### Test Case TC-21: Cryptographic Audit Trail (Genesis-to-Tip SHA-256 Chain)
* **Component:** Audit Trail (`pages/Audit.jsx`)
* **Expected Behavior:** Operator navigates to `/audit`. The audit log displays the chained event ledger for the campaign: timestamps, operator, event types (`CAMPAIGN_CREATED`, `CAMPAIGN_AUTHORIZED`, `CAMPAIGN_STARTED`, `TASK_COMPLETED`, `FINDING_VERIFIED`, `REPORT_GENERATED`), and chained SHA-256 event hashes with green `Chained` integrity badges.
* **GUI Route / Page:** `/audit?campaign=bda03f2c-9c9d-4de2-a902-4a35c371eecc`
* **Backend API Dependency:** `GET /api/campaigns/{id}/audit`
* **Test Data / Fixture Required:** Pre-seeded 4,875 audit events in `db/aihax.db`
* **Expected Visual Result:**
  * Table renders chronologically ordered events.
  * Operator column shows `lead_security_operator` or `system_service`.
  * Chained Hash Link column displays abbreviated SHA-256 hashes (`a94f...`).
  * Integrity column displays green checkmark: `Chained`.
* **Expected Backend Result:** HTTP 200 returning chained audit event records.
* **Evidence Required:** Browser screenshot of Audit Trail table.
* **Pass / Fail Criteria:** PASS if chained hashes and event types render cleanly; FAIL if empty or unchained.

---

### Test Case TC-22: Browser DevTools & Network Boundary Audit
* **Component:** Browser Console, Network Tab, and Security Boundaries
* **Expected Behavior:** Throughout the entire walkthrough, DevTools Console and Network tabs are inspected.
* **Verification Invariants:**
  1. **Zero Console Errors:** No unhandled JavaScript exceptions, no React render crashes, no error boundary falls.
  2. **Zero External Target Network Calls from Frontend:** The browser client only connects to `http://localhost:8000` (FastAPI backend). No direct network requests (fetch/XHR/WebSocket) are made from the browser to `https://www.mitacsc.ac.in` or external third parties.
  3. **Zero Leaked Secrets:** Request headers and URL queries do not expose secret API keys, private keys, or plain user passwords.
  4. **Blocked Actions Fail Closed:** Policy-blocked actions return appropriate 4xx status codes or are halted by the UI boundary before dispatch.
* **Evidence Required:** DevTools Console log snapshot and Network tab filter showing all origins are `localhost:8000` or `localhost:3000`.
* **Pass / Fail Criteria:** PASS if 0 external target calls and 0 console crashes; FAIL if frontend communicates directly with target.

---

## 5. Backend Correlation Trace Matrix

For key actions, the full execution chain will be traced and verified across all 6 platform layers:

```text
[ GUI Action ] ──► [ HTTP Request ] ──► [ Backend Service ] ──► [ Database Record ] ──► [ Audit Event ] ──► [ UI State ]
```

### Planned Correlation Checkpoints:
1. **Scope Pre-Flight Check:**
   * GUI: Click "Evaluate Scope" on `/targets`
   * HTTP: `POST /api/programs/{id}/validate-target`
   * Backend: `ScopeValidator.validate_target()`
   * DB: Verified against `programs.in_scope_assets`
   * Audit: Logged in transient safety audit
   * UI: Green banner `SCOPE VALIDATED`
2. **Finding Human Review:**
   * GUI: Click "Approve for Report" on `/findings/:id`
   * HTTP: `POST /api/findings/{id}/review`
   * Backend: `findings.py:review_finding()`
   * DB: `findings.human_review_status = 'APPROVED'`
   * Audit: `audit_trail_events.event_type = 'FINDING_REVIEWED'`
   * UI: Badge updates to `Review Status: APPROVED`
3. **Report Generation:**
   * GUI: Click "Generate" on `/reports`
   * HTTP: `POST /api/campaigns/{id}/reports`
   * Backend: `reports_service.generate_campaign_reports()`
   * DB: Report record inserted with SHA-256 manifest hash
   * Audit: `audit_trail_events.event_type = 'REPORT_GENERATED'`
   * UI: Download button enables, manifest count updates

---

## 6. Full Regression Testing Plan (Post-GUI Demonstration)

Following completion of the browser walkthrough, the full automated regression test suite will be executed to guarantee backend and frontend integrity:

1. **Backend Test Suites:**
   * `pytest backend/tests/test_phase27_certification_hardening.py`
   * `pytest backend/tests/test_phase26_*.py`
   * `pytest backend/tests/test_phase25_*.py`
   * `pytest backend/tests/test_phase23_*.py`
   * `pytest backend/tests/test_phase21_*.py`
   * `pytest backend/tests/test_phase18_*.py`
   * `pytest backend/tests/test_phase15_*.py`
   * `pytest backend/tests/test_request_engine.py`
   * `pytest backend/tests/test_scope_validator.py`
2. **Frontend Test Suites:**
   * `npm --prefix frontend test` (Vitest suite across 16 test files)
3. **Frontend Production Build:**
   * `npm --prefix frontend run build` (Vite production bundle compilation)

---

## 7. Deliverables & Output Artifacts

Upon execution of this plan, the following formal artifacts will be delivered:
1. **`docs/verification/full-system-gui-walkthrough.md`**: Complete 28-section final report with screenshots, backend correlations, regression numbers, failure analyses (if any), and final verdict.
2. **Browser Screenshots**: Captured via headless browser agent and saved in the artifacts directory.
3. **Final Summary**: Terminal summary conforming to the required format in user prompt Section 25.

---

## 8. Explicit Stop Condition

This document constitutes the formal **Full-System End-to-End GUI Verification Plan**. In strict accordance with Section 2 of the prompt:

> **"STOP after creating the plan. Do not begin implementation until the plan is internally complete."**

Implementation (launching servers, navigating the browser, running test suites) will begin immediately upon operator review and authorization.
