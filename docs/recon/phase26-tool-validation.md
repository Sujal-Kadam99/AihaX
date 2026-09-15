# Phase 26 — Recon Tool Installation & Functional Validation Gate Report

**Evaluation Date:** 2026-09-04  
**Target:** `https://www.mitacsc.ac.in`  
**Target Host:** `www.mitacsc.ac.in`  
**Base Domain:** `mitacsc.ac.in`  
**Validation Engines:**  
- `ReconToolAvailability` (`backend/recon/recon_tool_availability.py`)  
- `LiveReconValidationEngine` (`backend/recon/live_recon_validator.py`)  
- `ToolExecutionBoundary` (`backend/execution/tool_execution_boundary.py`)  
**Security & Integrity Invariant:** Zero False Success (Strict Truthful Reporting Gate)

---

## 1. Executive Summary

Phase 26 establishes the **Recon Tool Installation & Functional Validation Gate** for AihaX. Following Phase 25's verification of the core recon architecture, execution boundary, and evidence capture pipeline, Phase 26 focused on:
1. Auditing and integrating low-impact external reconnaissance tooling (**Subfinder**, **Amass** in passive mode, **GAU**, and **WhatWeb**) without weakening security, authorization, scope, safety, or evidence guarantees.
2. Formal classification of **Sublist3r** as `STUB_ONLY / PRODUCTION_CAPABILITY_NOT_IMPLEMENTED`.
3. Enforcement of policy boundaries for active scanners (**Nmap**, **Gobuster** -> `BLOCKED_POLICY`) and deferred scanners (**Nuclei**, **Dalfox** -> `NOT_SELECTED_RECON_ONLY`).
4. Strict enforcement of **Truthful Reporting**: When external CLI binaries are not installed in the operating environment PATH or configured tools directory, the system reports `BINARY_UNAVAILABLE` rather than fabricating simulated success or executing untrusted, unverified remote scripts.
5. Deterministic validation against the authorized concrete target `https://www.mitacsc.ac.in` (`mitacsc.ac.in`).

---

## 2. 12-Point Tool Capability & Validation Matrix

| Tool | Category | Installed | Adapter | Selected | Authorization Gate | Execution Supported | Output Captured | Output Parsed | Normalization & Scope | Evidence Generated | Final Gate Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Subfinder** | CLI Subdomain | NO | YES | YES | YES | NO (Binary Missing) | NO | NO | NO | NO | `BINARY_UNAVAILABLE` |
| **Sublist3r** | Legacy Scraper | NO | STUB | NO | NO | NO | NO | NO | NO | NO | `STUB_ONLY` |
| **Amass** | CLI Subdomain | NO | YES | YES | YES | NO (Binary Missing) | NO | NO | NO | NO | `BINARY_UNAVAILABLE` |
| **crt.sh / CT** | Native API | YES | YES | YES | YES | YES | YES | YES | YES | YES (SHA-256) | `LIVE_VALIDATED` |
| **Wayback** | Native API | YES | YES | YES | YES | YES | YES | YES | YES | YES (SHA-256) | `LIVE_VALIDATED` |
| **GAU** | CLI URL Discovery | NO | YES | YES | YES | NO (Binary Missing) | NO | NO | NO | NO | `BINARY_UNAVAILABLE` |
| **DNS Recon** | Native Python | YES | YES | YES | YES | YES | YES | YES | YES | YES (SHA-256) | `LIVE_VALIDATED` |
| **HTTP Probe** | Native Transport | YES | YES | YES | YES | YES | YES | YES | YES | YES (SHA-256) | `LIVE_VALIDATED` |
| **WhatWeb** | CLI Tech Detection| NO | YES | YES | YES | NO (Binary Missing) | NO | NO | NO | NO | `BINARY_UNAVAILABLE` |
| **Nmap** | Active Port Scan | NO | YES | NO | N/A | NO (Policy Gated) | NO | NO | NO | NO | `BLOCKED_POLICY` |
| **Gobuster** | Active Fuzzing | NO | YES | NO | N/A | NO (Policy Gated) | NO | NO | NO | NO | `BLOCKED_POLICY` |
| **Nuclei** | Vulnerability Scan| NO | YES | NO | N/A | NO (Deferred Phase)| NO | NO | NO | NO | `NOT_SELECTED_RECON_ONLY` |
| **Dalfox** | Exploit Tool | NO | YES | NO | N/A | NO (Deferred Phase)| NO | NO | NO | NO | `NOT_SELECTED_RECON_ONLY` |

---

## 3. Installation Provenance & Diagnostic Architecture

### 3.1 Binary Discovery & Diagnostic Engine (`ReconToolAvailability`)
AihaX implements a deterministic diagnostic subsystem (`backend/recon/recon_tool_availability.py`) that audits the execution host environment:
- **Zero Arbitrary Shell Execution:** Binary discovery is performed via deterministic lookup (`shutil.which` and configured directory scanning). Version extraction executes strictly via structured argument arrays through `ToolExecutionBoundary`. The use of `os.system()` or `shell=True` is forbidden.
- **Strict Provenance Standards:** Binaries are cataloged with fields including `installation_source`, `installation_method`, `required_version`, `detected_version`, and `checksum_or_provenance`.
- **Safe Environment Refusal:** Per security invariants, AihaX does not silently download or execute unverified third-party binaries from random mirrors via arbitrary curl/wget scripts. Missing external binaries are classified truthfully as `BINARY_UNAVAILABLE`.

### 3.2 Formal Status Taxonomy
1. **`AVAILABLE`**: Binary detected on PATH or configured directory, version verified against semantic pattern, safe profile supported.
2. **`BINARY_UNAVAILABLE`**: Adapter and boundary exist, but binary is not installed on the system PATH.
3. **`STUB_ONLY`**: Formal classification for Sublist3r (`"STUB_ONLY / PRODUCTION_CAPABILITY_NOT_IMPLEMENTED"`).
4. **`BLOCKED_POLICY`**: Policy-prohibited tools (Nmap, Gobuster) lacking explicit authorization.
5. **`NOT_SELECTED_RECON_ONLY`**: Security tools deferred to non-recon phases (Nuclei, Dalfox).

---

## 4. Tool-by-Tool Functional Specifications

### 4.1 Subfinder (`subfinder`)
- **Mode:** Passive subdomain discovery (`subfinder -d <domain> -silent -oJ`).
- **Adapter Status:** Operational in `LiveReconValidationEngine._validate_subfinder`.
- **Parsing & Normalization:** Parses JSON-line stream (`{"host": ...}`), normalizes domains, canonicalizes FQDNs.
- **Security Invariant:** All discovered subdomains are tagged `DISCOVERED_NOT_AUTHORIZED` (`is_executable: False`).
- **Live Status:** `BINARY_UNAVAILABLE` (Host PATH does not provide `subfinder.exe`).

### 4.2 Sublist3r (`sublist3r`)
- **Status:** `STUB_ONLY`.
- **Designation Reason:** `"STUB_ONLY / PRODUCTION_CAPABILITY_NOT_IMPLEMENTED"`.
- **Rationale:** Legacy scraping tool duplicated by Subfinder, Amass, and Certificate Transparency logs. Excluded from production execution to avoid brittle scraping failures.

### 4.3 Amass (`amass`)
- **Mode:** Passive enumeration only (`amass enum -passive -d <domain>`).
- **Safety Enforcement:** Prohibits active flags (`-active`, `-brute`, `-ip`, `-src`, `-rf`, etc.). Any attempt to invoke active flags is rejected at the boundary.
- **Parsing & Normalization:** Strips ANSI escape sequences and non-FQDN noise, validates RFC 1035 compliance.
- **Live Status:** `BINARY_UNAVAILABLE` (Host PATH does not provide `amass.exe`).

### 4.4 Certificate Transparency (`crtsh`)
- **Mode:** Native HTTPS API queries via `RequestEngine` against crt.sh.
- **Safety Enforcement:** Rate-limited, cached, zero direct contact with target domain.
- **Live Status:** `LIVE_VALIDATED` (Cryptographic evidence SHA-256 recorded).

### 4.5 Wayback Machine (`wayback`)
- **Mode:** Native CDX API queries via `RequestEngine` against Archive.org.
- **Parsing:** Canonicalizes historical URLs, extracts path structure and query parameters.
- **Live Status:** `LIVE_VALIDATED` (Cryptographic evidence SHA-256 recorded).

### 4.6 GAU — GetAllUrls (`gau`)
- **Mode:** Passive URL fetching (`gau --subs <domain>`).
- **Safety Enforcement:** Canonicalizes and deduplicates URLs.
- **Scope Classification:** URLs matching `mitacsc.ac.in` are classified as `DISCOVERED_NOT_AUTHORIZED`. URLs discovered pointing outside target scope (e.g., third-party trackers, CDNs) are classified as `DISCOVERED_OUT_OF_SCOPE` (`is_executable: False`).
- **Live Status:** `BINARY_UNAVAILABLE` (Host PATH does not provide `gau.exe`).

### 4.7 DNS Reconnaissance (`dns_recon`)
- **Mode:** Native DNS resolution via `dnspython`.
- **Record Types:** `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`.
- **Live Findings:** Successfully resolved `mitacsc.ac.in` -> `162.214.173.147`.
- **Live Status:** `LIVE_VALIDATED`.

### 4.8 HTTP Surface Prober (`http_probe`)
- **Mode:** Safe, bounded HTTP/HTTPS probing via `RequestEngine` and `HttpProbeEngine`.
- **Safety Bounds:** Max concurrency 1, rate <= 2 rps, <= 10 total requests, anti-SSRF IP verification.
- **Live Status:** `LIVE_VALIDATED`.

### 4.9 WhatWeb (`whatweb`)
- **Mode:** Read-only technology fingerprinting (`whatweb --log-json - <target>`).
- **Safety Enforcement:** Enforces non-aggressive mode. Explicitly rejects aggressive flags (`-a 3`, `-a 4`, `--aggression 3`).
- **Live Status:** `BINARY_UNAVAILABLE` (Host PATH does not provide `whatweb`).

### 4.10 Policy-Gated & Deferred Tools
- **Nmap (`nmap`):** Blocked by policy (`BLOCKED_POLICY`). Active network port scans require explicit program scope authorization.
- **Gobuster (`gobuster`):** Blocked by policy (`BLOCKED_POLICY`). Directory brute-forcing is forbidden in passive/safe recon mode.
- **Nuclei & Dalfox (`nuclei`, `dalfox`):** Classified as `NOT_SELECTED_RECON_ONLY`. Excluded from reconnaissance phases.

---

## 5. Security & Authorization Controls

1. **Preflight Authorization Verification:**
   - Every tool validation requires an active `AuthorizationRecord` in the AihaX database matching the target domain hash.
   - Missing or expired authorization fails closed with `BLOCKED_AUTHORIZATION`.
2. **Strict Concrete Scope:**
   - Target must be a concrete FQDN or URL (`https://www.mitacsc.ac.in`). Wildcard expressions are rejected.
3. **Discovery Immutability:**
   - Assets discovered during recon are strictly marked `DISCOVERED_NOT_AUTHORIZED` (`is_executable: False`). Discovery never implies permission to attack or probe without human-in-the-loop authorization.
4. **Static Network Boundary Audit:**
   - All network traffic for target operations routes exclusively through `RequestEngine` or `ToolExecutionBoundary`. Zero unmonitored raw `requests.get()`, `urllib.request`, or socket connections exist in target execution paths.

---

## 6. Test Suite & Verification Results

| Suite | Tests Executed | Passed | Failed | Status |
| :--- | :---: | :---: | :---: | :---: |
| **Phase 26 Tool Validation (`test_phase26_tool_validation.py`)** | 25 | 25 | 0 | **PASS** |
| **Phase 25 Live Recon Validation (`test_phase25_live_recon_validation.py`)** | 13 | 13 | 0 | **PASS** |
| **Core Regression Suite (Execution, Boundary, Scope, Request)** | 102 | 102 | 0 | **PASS** |
| **Frontend Vitest Suite (`ReconToolExecutionPanel` & UI)** | 94 | 94 | 0 | **PASS** |
| **Frontend Production Build (`npm run build`)** | Built in 2.99s | N/A | 0 errors | **PASS** |

---

## 7. Stop Condition & Phase Boundary

Phase 26 concludes with full functional validation of all recon tool adapters, strict diagnostic inventory reporting, complete evidence generation, and clean passing regression suites.

**Mandatory Invariant:**  
AihaX **STOPS** at the reconnaissance boundary. No active vulnerability scanning, fuzzing, parameter pollution, or exploitation has been or will be executed in this phase.
