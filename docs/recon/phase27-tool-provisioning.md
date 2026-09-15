# Phase 27 — Approved Recon Tool Provisioning & Functional Validation Gate Report

**Evaluation Date:** 2026-09-05  
**Target:** `https://www.mitacsc.ac.in`  
**Target Host:** `www.mitacsc.ac.in`  
**Base Domain:** `mitacsc.ac.in`  
**Campaign ID:** `phase27-mitacsc-auth-camp`  
**Authorization Record:** `auth-mitacsc-phase27-record-valid` (STATUS: `ACTIVE`, operator confirmed)  
**Tools Directory:** `bin/tools` (`AIHAX_TOOLS_DIR`)  
**Security & Integrity Invariants:** Zero False Success; No Shell Execution (`shell=False`); Zero Vulnerability Scanning / Fuzzing / Exploitation.

---

## 1. Executive Summary

Phase 27 closes the external tooling gap documented in Phase 26. In Phase 26, the recon availability subsystem, execution boundaries, safety profiles, parsers, evidence capture, and capability matrix were fully hardened, but all external CLI tools reported `BINARY_UNAVAILABLE`.

In Phase 27, AihaX executed the **Approved Recon Tool Provisioning & Functional Validation Gate**:
1. **Provenance-Verified Tool Provisioning:** Four approved, low-impact reconnaissance tools (**Subfinder**, **Amass**, **GAU**, and **WhatWeb**) were provisioned into the project-local tools directory `bin/tools/` from official upstream GitHub release assets. Zero untrusted mirrors, zero arbitrary curl/bash download scripts, and zero global system PATH pollution.
2. **Reinstall Prevention & Provenance Auditing:** The `ReconToolProvisioner` subsystem performs pre-install inventory validation, hash/release verification, and skips redundant downloads if valid binaries are present.
3. **Hardened Execution Boundary & Invariant Preservation:** Subprocess calls remain strictly `shell=False` via `asyncio.create_subprocess_exec`, bounded by per-tool argument whitelists, anti-injection filters, strict timeouts, and output size caps.
4. **Controlled Live Functional Validation:** Under explicit authorization on concrete target `https://www.mitacsc.ac.in`, all four provisioned tools plus native DNS and HTTP probing achieved **`LIVE_VALIDATED`** status:
   $$\text{Execution} \longrightarrow \text{Output} \longrightarrow \text{Parsing} \longrightarrow \text{Normalization} \longrightarrow \text{Evidence SHA-256} \longrightarrow \text{ReconSnapshot} \longrightarrow \text{AttackSurfaceGraph}$$
5. **Strict Scope & Non-Executable Invariants:** 5,896 normalized assets were ingested into `ReconSnapshot` (hash: `2a1e6f47567d85a0dbb49417675680fd7f2601aff699f936bc585f1643f5a9c2`) and 5,822 nodes into `AttackSurfaceGraph` (hash: `d5a7b6fcd447ffb1a4e87a9ab409851c1ed315229b33aad28cda517b0dd8d171`). Every discovered asset is flagged `is_executable: False` with authorization status `DISCOVERED_NOT_AUTHORIZED` (or `DISCOVERED_OUT_OF_SCOPE`).
6. **Zero Vulnerability Scanning / Fuzzing / Exploitation:** Execution stopped immediately upon reconnaissance completion. Policy-prohibited active tools (**Nmap**, **Gobuster**) remained `BLOCKED_POLICY`, deferred scanners (**Nuclei**, **Dalfox**) remained `NOT_SELECTED_RECON_ONLY`, and **Sublist3r** remained `STUB_ONLY`.

---

## 2. Before / After Capability & Validation Matrix

| Tool | Category | Phase 26 Status | Phase 27 Provisioning | Version Detected | Live Output Captured | Parsed & Normalized | Evidence SHA-256 | Phase 27 Final Gate Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Subfinder** | CLI Subdomain | `BINARY_UNAVAILABLE` | GitHub Releases v2.16.0 | `v2.16.0` | YES (47 subdomains) | YES (47 assets) | `f3137999d732e62f...` | `LIVE_VALIDATED` |
| **Amass** | CLI Subdomain | `BINARY_UNAVAILABLE` | GitHub Releases v5.1.1 | `v5.1.1` | YES (3 subdomains) | YES (3 assets) | `9ea45530c6b030a7...` | `LIVE_VALIDATED` |
| **GAU** | CLI URL Discovery | `BINARY_UNAVAILABLE` | GitHub Releases v2.2.4 | `v2.2.4` | YES (5,820 URLs) | YES (5,820 endpoints)| `82e72e27f6ef4d2f...` | `LIVE_VALIDATED` |
| **WhatWeb** | CLI Tech Fingerprint| `BINARY_UNAVAILABLE`| GitHub v0.6.4 + Ruby 3.3 | `v0.6.4` | YES (1 target JSON) | YES (1 tech asset) | `803b7c54e28da827...` | `LIVE_VALIDATED` |
| **DNS Recon** | Native Python | `LIVE_VALIDATED` | Native dnspython | N/A | YES (11 DNS records) | YES (11 assets) | `9b36661afab1a3bf...` | `LIVE_VALIDATED` |
| **HTTP Probe**| Native Transport | `LIVE_VALIDATED` | Native RequestEngine | N/A | YES (1 HTTP probe) | YES (1 endpoint asset)| `f6ae5e7ccc6dd79c...` | `LIVE_VALIDATED` |
| **crt.sh / CT**| Native API | `LIVE_VALIDATED` | Native HTTPS client | N/A | YES (0 entries logged)| YES (0 assets) | `4f53cda18c2baa0c...` | `EXECUTED_ZERO_RESULTS`|
| **Wayback** | Native API | `LIVE_VALIDATED` | Native CDX client | N/A | YES (0 entries logged)| YES (0 assets) | `4f53cda18c2baa0c...` | `EXECUTED_ZERO_RESULTS`|
| **Sublist3r** | Legacy Scraper | `STUB_ONLY` | Excluded by Policy | N/A | NO | NO | N/A | `STUB_ONLY` |
| **Nmap** | Active Port Scanner| `BLOCKED_POLICY` | Excluded by Policy | N/A | NO | NO | N/A | `BLOCKED_POLICY` |
| **Gobuster** | Active Fuzzer | `BLOCKED_POLICY` | Excluded by Policy | N/A | NO | NO | N/A | `BLOCKED_POLICY` |
| **Nuclei** | Vulnerability Scan | `NOT_SELECTED_RECON_ONLY`| Excluded (Recon Only)| N/A | NO | NO | N/A | `NOT_SELECTED_RECON_ONLY`|
| **Dalfox** | Active XSS Scanner | `NOT_SELECTED_RECON_ONLY`| Excluded (Recon Only)| N/A | NO | NO | N/A | `NOT_SELECTED_RECON_ONLY`|

---

## 3. Approved Installation Provenance

External tools were provisioned strictly via `ReconToolProvisioner` (`backend/recon/recon_tool_provisioner.py`) into the isolated local workspace path `bin/tools/`:

### 3.1 Subfinder
- **Tool Name:** `subfinder`
- **Upstream Source:** `projectdiscovery/subfinder` (Official GitHub Release)
- **Asset URL:** `https://github.com/projectdiscovery/subfinder/releases/download/v2.16.0/subfinder_2.16.0_windows_amd64.zip`
- **Local Binary:** `bin\tools\subfinder.exe`
- **Detected Version:** `v2.16.0`
- **Packaging:** Zip archive containing standalone Go binary.

### 3.2 Amass
- **Tool Name:** `amass`
- **Upstream Source:** `owasp-amass/amass` (Official GitHub Release)
- **Asset URL:** `https://github.com/owasp-amass/amass/releases/download/v5.1.1/amass_windows_amd64.zip`
- **Local Binary:** `bin\tools\amass.exe`
- **Detected Version:** `v5.1.1`
- **Packaging:** Zip archive containing standalone Go binary.
- **Enforced Execution Mode:** Passive OSINT collection only (`enum -passive -d <domain> -timeout 1`). Active, brute-force, and alteration flags are rejected at the boundary.

### 3.3 GAU (GetAllUrls)
- **Tool Name:** `gau`
- **Upstream Source:** `lc/gau` (Official GitHub Release)
- **Asset URL:** `https://github.com/lc/gau/releases/download/v2.2.4/gau_2.2.4_windows_amd64.tar.gz`
- **Local Binary:** `bin\tools\gau.exe`
- **Detected Version:** `v2.2.4`
- **Packaging:** Tar.gz archive containing standalone Go binary.
- **Scope Classification:** Discovered URLs matching scope are tagged `DISCOVERED_NOT_AUTHORIZED`. External URLs are tagged `DISCOVERED_OUT_OF_SCOPE`. All are tagged `is_executable: False`.

### 3.4 WhatWeb
- **Tool Name:** `whatweb`
- **Upstream Source:** `urbanadventurer/WhatWeb` (Official GitHub Release v0.6.4)
- **Asset URL:** `https://github.com/urbanadventurer/WhatWeb/archive/refs/tags/v0.6.4.tar.gz`
- **Repository Location:** `bin/tools/whatweb_repo`
- **Execution Wrapper:** `bin\tools\whatweb.bat` executing `C:\Ruby33-x64\bin\ruby.exe` with `addressable` gem.
- **Detected Version:** `v0.6.4`
- **Enforced Mode:** Read-only technology identification (`--log-json - --quiet <target>`). Aggression levels `-a 3` or `-a 4` are strictly blocked.

### 3.5 Reinstall Prevention
The provisioner inspects existing binaries in `bin/tools/` before attempting network downloads. If a verified executable is present and matches the required name, downloading is skipped:
```python
if os.path.isfile(dest_path) and os.path.getsize(dest_path) > 0:
    return dest_path  # Reinstall avoided
```

---

## 4. Security, Scope & Isolation Controls

1. **Zero Shell Invocation:**
   - All subprocess calls use `asyncio.create_subprocess_exec(*cmd_argv, stdout=PIPE, stderr=PIPE)`.
   - `shell=True` and `os.system()` are strictly prohibited and verified via AST static analysis.
2. **Execution Boundary Invariant:**
   - External CLI subprocess execution is blocked unless the request explicitly specifies `execution_mode="AUTHORIZED_LIVE_RECON"`. Default audit requests fail-closed.
3. **Discovered Assets Remain Non-Executable:**
   - Every asset produced by Subfinder, Amass, GAU, or WhatWeb receives `is_executable: False`.
   - Discovery never confers authorization. Discovered assets cannot be passed to active attack or scanning engines.
4. **Policy-Blocked Tools Remain Blocked:**
   - Nmap and Gobuster require separate explicit operator policy overrides (`allow_port_scan=True`, `allow_dir_scan=True`). Without these, they are immediately classified as `BLOCKED_POLICY`.
   - Nuclei and Dalfox are active vulnerability scanners and remain permanently classified as `NOT_SELECTED_RECON_ONLY` during reconnaissance.
   - Sublist3r is retained as `STUB_ONLY / PRODUCTION_CAPABILITY_NOT_IMPLEMENTED`.

---

## 5. Test Suite & Regression Verification

### 5.1 Backend Pytest Suite
All 119 backend unit, integration, and security tests passed in 9.97 seconds:
- `backend/tests/test_phase27_recon_tool_provisioning.py`: **17 passed**
- `backend/tests/test_phase26_tool_validation.py`: **25 passed**
- `backend/tests/test_phase25_live_recon_validation.py`: **13 passed**
- `backend/tests/test_phase15_execution_boundary.py`: **2 passed**
- `backend/tests/test_recon_modes_and_security.py`: **15 passed**
- `backend/tests/test_scope_validator.py`: **23 passed**
- `backend/tests/test_request_engine.py`: **24 passed**
- **Total:** **119 passed, 0 failed, 3 warnings**

### 5.2 Frontend Vitest Suite
All 16 test files and 94 tests passed in 5.88 seconds:
- `src/test/EvidenceVisibility.test.jsx`: **21 passed**
- `src/test/NewAssessmentCrashInvestigation.test.jsx`: **19 passed**
- `src/test/UrlValidator.test.jsx`: **13 passed**
- Remaining suites (VerificationQueue, EvidenceTimeline, etc.): **41 passed**
- **Total:** **94 passed, 0 failed**

### 5.3 Frontend Production Build
`npm run build` completed successfully with 0 errors in 3.31s:
```text
dist/index.html                   1.35 kB │ gzip:   0.67 kB
dist/assets/index-l71CEFc6.css   45.84 kB │ gzip:   8.92 kB
dist/assets/index-CnsgLHQD.js   534.74 kB │ gzip: 141.25 kB
✓ built in 3.31s
```

### 5.4 Static Security Audit (AST Analysis)
Automated AST static audit of all files in `backend/recon` and `backend/services/discovery`:
- `shell=True` occurrences: **0**
- `os.system()` / `os.popen()` occurrences: **0**
- Direct raw network calls (`requests.`, `httpx.`, `urllib.` outside provisioner): **0**
- **Result:** `STATIC SECURITY AUDIT: PASSED (0 violations)`

---

## 6. Authorized Live Functional Validation Matrix

**Execution Command:** `.venv\Scripts\python.exe -m backend.recon.run_phase27_live_recon`  
**Execution Context:** `AIHAX_TOOLS_DIR = C:\Users\sujal\OneDrive\Documents\Desktop\Aihax\bin\tools`  
**Target:** `https://www.mitacsc.ac.in`  
**Suite Status:** `VALIDATION_COMPLETE`

| Tool | Status | Exit Code | Parsed Results | Normalized Results | Snapshot Contribution | Raw Stdout SHA-256 |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **subfinder** | `LIVE_VALIDATED` | 0 | 47 | 47 | 47 subdomains | `f3137999d732e62f...` |
| **sublist3r** | `STUB_ONLY` | None | 0 | 0 | 0 | None (Intentionally not executed) |
| **amass** | `LIVE_VALIDATED` | 0 | 3 | 3 | 3 subdomains | `9ea45530c6b030a7...` |
| **crtsh** | `EXECUTED_ZERO_RESULTS` | 0 | 0 | 0 | 0 | `4f53cda18c2baa0c...` |
| **wayback** | `EXECUTED_ZERO_RESULTS` | 0 | 0 | 0 | 0 | `4f53cda18c2baa0c...` |
| **gau** | `LIVE_VALIDATED` | 0 | 5,820 | 5,820 | 5,820 endpoints | `82e72e27f6ef4d2f...` |
| **dns_recon** | `LIVE_VALIDATED` | 0 | 11 | 11 | 11 DNS records | `9b36661afab1a3bf...` |
| **http_probe** | `LIVE_VALIDATED` | 0 | 1 | 1 | 1 endpoint | `f6ae5e7ccc6dd79c...` |
| **whatweb** | `LIVE_VALIDATED` | 0 | 1 | 1 | 1 tech asset | `803b7c54e28da827...` |
| **nmap** | `BLOCKED_POLICY` | None | 0 | 0 | 0 | None (Port scan unauthorized) |
| **gobuster** | `BLOCKED_POLICY` | None | 0 | 0 | 0 | None (Directory fuzzing unauthorized) |
| **nuclei** | `NOT_SELECTED_RECON_ONLY`| None | 0 | 0 | 0 | None (Vulnerability scanner excluded)|
| **dalfox** | `NOT_SELECTED_RECON_ONLY`| None | 0 | 0 | 0 | None (XSS scanner excluded) |

---

## 7. Discovered Assets, Evidence & Graph Integrity

### 7.1 ReconSnapshot Integrity
- **Snapshot Hash:** `2a1e6f47567d85a0dbb49417675680fd7f2601aff699f936bc585f1643f5a9c2`
- **Total Normalized Assets Ingested:** 5,896
- **Sample Discovered Assets:**
  - `www.mitacsc.ac.in` (`DOMAIN`) — source: `seed_target`
  - `pragmatic88.mitacsc.ac.in` (`SUBDOMAIN`) — source: `subfinder`
  - `cpanel.mitacsc.ac.in` (`SUBDOMAIN`) — source: `subfinder`
  - `mumbai.mitacsc.ac.in` (`SUBDOMAIN`) — source: `subfinder`
  - `tototogel.mitacsc.ac.in` (`SUBDOMAIN`) — source: `subfinder`
  - `webmail.mitacsc.ac.in` (`SUBDOMAIN`) — source: `subfinder`
  - `autodiscover.server.mitacsc.ac.in` (`SUBDOMAIN`) — source: `subfinder`
  - `admission.mitacsc.ac.in` (`SUBDOMAIN`) — source: `subfinder`
  - `www.toto4d.mitacsc.ac.in` (`SUBDOMAIN`) — source: `subfinder`
  - `cpcalendars.server.mitacsc.ac.in` (`SUBDOMAIN`) — source: `subfinder`
  - `https://apply.mitacsc.ac.in/form/submit/...` (`ENDPOINT`) — source: `gau`
  - `http://exam.mitacsc.ac.in/` (`ENDPOINT`) — source: `gau`
  - `https://www.mitacsc.ac.in:apache` (`TECHNOLOGY`) — source: `whatweb`
  - `mitacsc.ac.in:A:162.214.173.147` (`IP_ADDRESS`) — source: `dns_recon`

### 7.2 AttackSurfaceGraph Integrity
- **Graph Snapshot Hash:** `d5a7b6fcd447ffb1a4e87a9ab409851c1ed315229b33aad28cda517b0dd8d171`
- **Total Graph Nodes:** 5,822
- **Node Classification:** Target node, subdomain nodes, endpoint nodes, and service nodes correctly connected without exploratory attack edges.

### 7.3 Cryptographic Evidence
Every tool execution generated an independent cryptographic SHA-256 digest of raw process output (`stdout_hash`). Evidence hashes are immutable and bound to each `ToolExecutionRecord`.

---

## 8. Stop Condition Enforcement

**Mandatory Invariant Verification:**
- Fuzzing performed: **0 requests**
- Port scans performed: **0 ports scanned**
- Exploit attempts performed: **0 payloads sent**
- Vulnerability scans executed: **0 tests run**

Phase 27 operations concluded strictly at authorized passive reconnaissance asset discovery, normalization, cryptographic evidence generation, and graph update. Execution halted per security guidelines.
