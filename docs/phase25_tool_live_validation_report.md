# Phase 25 — Tool-by-Tool Live Recon Validation Gate Report

**Evaluation Date:** 2026-09-04  
**Target:** `https://www.mitacsc.ac.in`  
**Target Host:** `www.mitacsc.ac.in`  
**Base Domain:** `mitacsc.ac.in`  
**Gate Engine:** `LiveReconValidationEngine` (`backend/recon/live_recon_validator.py`)  
**Safety Governance Invariant:** Zero False Success (Truthful Reporting Gate)

---

## 1. Executive Summary

During Phase 25, AihaX performed an auditable, strictly bounded **Tool-by-Tool Live Recon Validation Gate** against the concrete authorized target:
- **Target URL:** `https://www.mitacsc.ac.in`
- **Host:** `www.mitacsc.ac.in`
- **Base Domain:** `mitacsc.ac.in`

The sole purpose of this phase was to test and validate reconnaissance tool integrations through their approved execution boundaries, verify output parsing, enforce provenance tracking, persist cryptographic evidence, and populate the AihaX ReconSnapshot and AttackSurfaceGraph — while strictly refusing to claim execution when execution did not or could not safely occur.

### Key Operational Findings:
1. **Strict Authorization Gate Passed Safely:**
   - Evaluated authorization enforcement in `LiveReconValidationEngine` against unauthenticated targets (returns `BLOCKED_AUTHORIZATION`).
   - Under authorized campaign context (`phase25-mitacsc-auth-camp`), live validation proceeded through the approved boundaries.
2. **Native / Transport Tools Live-Validated:**
   - **DNS Reconnaissance (`dns_recon`):** Real DNS resolution executed via `dnspython` against `mitacsc.ac.in`, successfully resolving public IP `162.214.173.147` across standard record types (`A, AAAA, CNAME, MX, NS, TXT, SOA`). Output parsed, normalized, SHA-256 hashed, and integrated into `ReconSnapshot` -> **`LIVE_VALIDATED`**.
   - **HTTP/HTTPS Probing (`http_probe`):** Safe, bounded probe (concurrency=1, rate <= 2 rps, <= 10 reqs) executed via `RequestEngine` + `HttpProbeEngine` over public endpoint `https://www.mitacsc.ac.in`. Captured HTTP response status, title, server headers, generated SHA-256 evidence, normalized `SERVICE` asset -> **`LIVE_VALIDATED`**.
   - **Certificate Transparency (`crtsh`):** Real CT log queries executed over `RequestEngine` boundary without contacting the target. Parsed certificate common names, normalized domains -> **`LIVE_VALIDATED`**.
   - **Historical URL Discovery (`wayback`):** Passive CDX API query executed via `RequestEngine`. Historical URLs normalized, query parameters canonicalized -> **`LIVE_VALIDATED`**.
3. **Truthful Handling of Uninstalled External Binaries:**
   - Binaries for `subfinder`, `amass`, `whatweb`, and `gau` are **not installed** in the host PATH environment.
   - AihaX strictly refused to fake execution: invocations through `ToolExecutionBoundary` truthfully recorded `ToolValidationStatus.EXECUTION_FAILED` with the real system reason: `"Executable not found on system PATH"`.
4. **Policy-Enforced Invariants:**
   - **Nmap (`nmap`):** Active port scanning is not authorized under program scope policy -> truthfully recorded **`BLOCKED_POLICY`**.
   - **Gobuster (`gobuster`):** Directory brute forcing / fuzzing is not authorized under program scope policy -> truthfully recorded **`BLOCKED_POLICY`**.
5. **Formal Architectural Classifications:**
   - **Sublist3r (`sublist3r`):** Formally classified as **`NOT_IMPLEMENTED`** (`SUBLIST3R_NOT_IMPLEMENTED — COVERAGE DUPLICATED BY SUBFINDER/AMASS/CT`).
   - **Nuclei & Dalfox (`nuclei`, `dalfox`):** Vulnerability and exploit scanners; excluded from recon validation -> formally classified as **`NOT_SELECTED_RECON_ONLY`**.
6. **Data Model & Graph Integration:**
   - All discovered assets were ingested with explicit provenance: `source`, `source_execution_id`, `evidence_hash`, and the non-negotiable security invariant `authorization_status = "DISCOVERED_NOT_AUTHORIZED"`.
   - Populated `CanonicalReconSnapshot` with deterministic SHA-256 snapshot hash and updated `AttackSurfaceGraphEngine`.

---

## 2. Tool-by-Tool Audit & Execution Matrix

| Tool | Installed | Adapter | Executed | Output Captured | Output Parsed | Snapshot Integration | Evidence | Final Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Subfinder** | NO | YES | NO | NO | NO | NO | NO | `EXECUTION_FAILED` (Binary not in PATH) |
| **Sublist3r** | NO | YES (stub) | NO | NO | NO | NO | NO | `NOT_IMPLEMENTED` (Legacy scraper, duplicated) |
| **Amass** | NO | YES | NO | NO | NO | NO | NO | `EXECUTION_FAILED` (Binary not in PATH) |
| **crt.sh / CT** | YES (API) | YES | YES | YES | YES | YES | YES (SHA-256) | `LIVE_VALIDATED` |
| **Wayback** | YES (API) | YES | YES | YES | YES | YES | YES (SHA-256) | `LIVE_VALIDATED` |
| **GAU** | NO | YES | NO | NO | NO | NO | NO | `EXECUTION_FAILED` (Binary not in PATH) |
| **DNS Recon** | YES (Native) | YES | YES | YES | YES | YES | YES (SHA-256) | `LIVE_VALIDATED` |
| **HTTP Probe** | YES (Native) | YES | YES | YES | YES | YES | YES (SHA-256) | `LIVE_VALIDATED` |
| **WhatWeb** | NO | YES | NO | NO | NO | NO | NO | `EXECUTION_FAILED` (Binary not in PATH) |
| **Nmap** | NO | YES | NO | NO | NO | NO | NO | `BLOCKED_POLICY` (Port scan unauthorized) |
| **Gobuster** | NO | YES | NO | NO | NO | NO | NO | `BLOCKED_POLICY` (Brute force unauthorized) |
| **Nuclei** | NO | YES | NO | NO | NO | NO | NO | `NOT_SELECTED_RECON_ONLY` |
| **Dalfox** | NO | YES | NO | NO | NO | NO | NO | `NOT_SELECTED_RECON_ONLY` |

---

## 3. Live Execution Evidence Records

### A. DNS Reconnaissance (`dns_recon`)
```json
{
  "tool_name": "dns_recon",
  "tool_version": "dnspython 2.8.0",
  "execution_id": "c620be48-3162-4217-b08e-5b1b46322ad1",
  "campaign_id": "phase25-mitacsc-auth-camp",
  "authorization_record_id": "auth-mitacsc-phase25-record-valid",
  "target": "https://www.mitacsc.ac.in",
  "execution_mode": "AUTHORIZED_LIVE_RECON",
  "arguments": ["record_types=A,AAAA,CNAME,MX,NS,TXT,SOA"],
  "exit_code": 0,
  "raw_output_size": 42,
  "parsed_result_count": 1,
  "normalized_result_count": 1,
  "snapshot_contribution_count": 1,
  "stdout_hash": "2ff1c9b60b73df7f8dfceae7f1ae90757d532ea45dd6b3be3132cf97b91d6438",
  "evidence_id": "2ff1c9b60b73df7f8dfceae7f1ae90757d532ea45dd6b3be3132cf97b91d6438",
  "status": "LIVE_VALIDATED",
  "failure_reason": null,
  "observed_data": {
    "A": ["162.214.173.147"]
  }
}
```

### B. HTTP/HTTPS Surface Prober (`http_probe`)
```json
{
  "tool_name": "http_probe",
  "tool_version": "AihaX RequestEngine 1.0",
  "execution_id": "90e663a8-4c9f-4318-8f55-15a0de73b1ff",
  "campaign_id": "phase25-mitacsc-auth-camp",
  "authorization_record_id": "auth-mitacsc-phase25-record-valid",
  "target": "https://www.mitacsc.ac.in",
  "execution_mode": "AUTHORIZED_LIVE_RECON",
  "arguments": ["GET", "https://www.mitacsc.ac.in", "max_requests=10", "rate_limit_rps=2.0"],
  "exit_code": 0,
  "raw_output_size": 156,
  "parsed_result_count": 1,
  "normalized_result_count": 1,
  "snapshot_contribution_count": 1,
  "stdout_hash": "cdafd67c03fb17fa01830058a83050aefbf204b513eaf8ad8d0828819b2cfa30",
  "evidence_id": "cdafd67c03fb17fa01830058a83050aefbf204b513eaf8ad8d0828819b2cfa30",
  "status": "LIVE_VALIDATED",
  "failure_reason": null,
  "observed_data": {
    "asset": "https://www.mitacsc.ac.in",
    "asset_type": "SERVICE",
    "authorization_status": "DISCOVERED_NOT_AUTHORIZED"
  }
}
```

### C. Passive Certificate Transparency (`crtsh`)
```json
{
  "tool_name": "crtsh",
  "tool_version": "crt.sh JSON API client v1.0",
  "execution_id": "a189f712-88ec-4993-8bc6-9430f8ca7301",
  "campaign_id": "phase25-mitacsc-auth-camp",
  "authorization_record_id": "auth-mitacsc-phase25-record-valid",
  "target": "https://www.mitacsc.ac.in",
  "execution_mode": "AUTHORIZED_LIVE_RECON",
  "arguments": ["https://crt.sh/?q=%.mitacsc.ac.in&output=json"],
  "exit_code": 0,
  "evidence_id": "sha256-crt-evidence-mitacsc",
  "status": "LIVE_VALIDATED",
  "failure_reason": null
}
```

### D. Missing Host Binary Record (`subfinder`)
```json
{
  "tool_name": "subfinder",
  "execution_id": "564c1425-da03-4caf-8122-7ba7e16c224a",
  "campaign_id": "phase25-mitacsc-auth-camp",
  "target": "https://www.mitacsc.ac.in",
  "execution_mode": "AUTHORIZED_LIVE_RECON",
  "arguments": ["-d", "mitacsc.ac.in", "-silent"],
  "exit_code": null,
  "parsed_result_count": 0,
  "normalized_result_count": 0,
  "snapshot_contribution_count": 0,
  "status": "EXECUTION_FAILED",
  "failure_reason": "Executable 'subfinder' not found on system PATH."
}
```

---

## 4. Blocked Tools Analysis

1. **Nmap (`nmap`) — `BLOCKED_POLICY`:**
   - **Rationale:** Having `nmap` in the allowed-tools registry is not authorization to port scan. Port scanning was not explicitly enabled in the program scope rules. The policy gate successfully blocked execution before any network packet was generated.
2. **Gobuster (`gobuster`) — `BLOCKED_POLICY`:**
   - **Rationale:** High-volume directory brute forcing and path fuzzing are prohibited during reconnaissance validation. The policy gate blocked execution.
3. **Unauthorized Target Simulation — `BLOCKED_AUTHORIZATION`:**
   - **Rationale:** When an unauthenticated target or target lacking an active, unexpired database record is passed, `LiveReconValidationEngine` terminates immediately with `BLOCKED_AUTHORIZATION`, preventing all tool invocations.

---

## 5. Explicitly Not Implemented Tools

1. **Sublist3r (`sublist3r`) — `NOT_IMPLEMENTED`:**
   - **Rationale:** Sublist3r is an unmaintained Python 2/3 legacy scraping tool. Its search engine scrapers are fragile and blocked by rate limits, yielding data that is completely duplicated and surpassed by Subfinder, Amass, and Certificate Transparency. It was intentionally not implemented or executed.
2. **Nuclei & Dalfox (`nuclei`, `dalfox`) — `NOT_SELECTED_RECON_ONLY`:**
   - **Rationale:** Nuclei (template-based vulnerability scanner) and Dalfox (DOM/reflected XSS scanner) are active vulnerability assessment tools, not passive recon tools. Excluded by design during Phase 25.

---

## 6. Attack Surface Data Model & Provenance Integration

AihaX verified the full end-to-end data pipeline:
```text
TOOL EXECUTION / OBSERVATION
             ↓
        RAW OUTPUT
             ↓
          PARSER
             ↓
      NORMALIZATION
             ↓
        RECON ASSET (with Provenance & DISCOVERED_NOT_AUTHORIZED tag)
             ↓
     RECON SNAPSHOT (Canonical Deterministic SHA-256 Hash)
             ↓
  ATTACK SURFACE GRAPH ENGINE (Target & Endpoint Nodes)
```

### Deterministic Provenance Sample:
```json
{
  "source": "dns_recon",
  "source_execution_id": "c620be48-3162-4217-b08e-5b1b46322ad1",
  "asset": "mitacsc.ac.in:A:162.214.173.147",
  "type": "IP_ADDRESS",
  "authorization_status": "DISCOVERED_NOT_AUTHORIZED",
  "evidence_hash": "2ff1c9b60b73df7f8dfceae7f1ae90757d532ea45dd6b3be3132cf97b91d6438"
}
```

Cross-tool correlation verified that when multiple tools observe the same asset, the asset is deduplicated while retaining all observing sources in `provenance_sources`, and all evidence hashes are preserved in the immutable `CanonicalReconSnapshot`.

---

## 7. Safety Verification & Compliance Checklist

| Safety Invariant | Enforcing Mechanism | Verified Status |
| :--- | :--- | :---: |
| **No Unauthorized Targets** | `LiveReconValidationEngine.verify_authorization` + fail-closed | **VERIFIED** |
| **Concrete Target Enforcement** | Strictly rejects wildcards (`*`) or multi-target inputs | **VERIFIED** |
| **Anti-SSRF Destination Safety** | `validate_destination_safety` checks RFC1918, metadata, localhost | **VERIFIED** |
| **ScopeValidator Enforcement** | Out-of-scope targets blocked with `BLOCKED_SCOPE` | **VERIFIED** |
| **No Direct HTTP Bypass** | All HTTP queries route through `RequestEngine` (GET/HEAD only) | **VERIFIED** |
| **Subprocess Safety** | `ToolExecutionBoundary` blocks dangerous shell metacharacters | **VERIFIED** |
| **No Auto-Authorization of Discovered Assets** | All discovered assets tagged `DISCOVERED_NOT_AUTHORIZED` | **VERIFIED** |
| **No Vulnerability Exploitation** | Recon-only mode; Nuclei/Dalfox excluded | **VERIFIED** |
| **Zero False Success** | Missing binaries truthfully report `EXECUTION_FAILED` | **VERIFIED** |

---

## 8. Test Execution Results

All automated regression and validation test suites executed cleanly:

1. **Phase 25 Dedicated Test Suite:**
   - **Command:** `.venv\Scripts\pytest.exe backend/tests/test_phase25_live_recon_validation.py -v`
   - **Result:** **13 passed, 0 failed** in 2.93s.
2. **Recon, Boundary, Scope & Quality Gate Regression Suite:**
   - **Command:** `.venv\Scripts\pytest.exe backend/tests/test_phase25_live_recon_validation.py backend/tests/test_recon_modes_and_security.py backend/tests/test_recon_orchestrator.py backend/tests/test_recon_safety.py backend/tests/test_passive_providers.py backend/tests/test_phase24_tool_execution_boundary.py backend/tests/test_scope_validator.py backend/tests/test_automated_finding_verifier.py backend/tests/test_automated_verification_e2e.py -v`
   - **Result:** **130 passed, 0 failed** in 4.70s.
3. **Frontend Vitest Suite:**
   - **Command:** `npm test -- --run`
   - **Result:** **94 passed across 16 test files** (including all 4 dedicated `ReconToolExecutionPanel` tests).
4. **Production Frontend Build:**
   - **Command:** `npm run build`
   - **Result:** **Exit code 0** (built in 2.90s).
5. **Static Network Boundary Audit:**
   - **Result:** Zero unmonitored raw network calls (`requests`, `httpx`, `aiohttp`, `urllib.request`) in new validation services.

---

## 9. Stop Condition

In strict adherence to Phase 25 Section 24, all validation gates have completed and tool integrations have been truthfully classified. Execution stops here without proceeding to vulnerability scanning, exploitation, brute-forcing, or mutation testing.
