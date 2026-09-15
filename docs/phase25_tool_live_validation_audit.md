# Phase 25 — Tool-by-Tool Live Recon Validation Audit

**Audit Date:** 2026-09-04  
**Target Host:** `www.mitacsc.ac.in`  
**Base Domain:** `mitacsc.ac.in`  
**Concrete Target:** `https://www.mitacsc.ac.in`  
**Auditor:** AihaX Automated Governance & Security Architecture  

---

## 1. Executive Summary

This pre-execution audit evaluates all 13 candidate reconnaissance and discovery tools identified in the AihaX architecture:
1. Subfinder
2. Sublist3r
3. Amass
4. Certificate Transparency (crt.sh)
5. Wayback (Archive.org CDX API & waybackurls)
6. GAU (GetAllUrls)
7. DNS Enumeration
8. HTTP/HTTPS Probing
9. WhatWeb
10. Nmap
11. Gobuster
12. Nuclei
13. Dalfox

This audit establishes whether each tool has an active executable on the host system, an approved adapter, an execution path from `ReconOrchestrator` / `ReconAgent`, strict execution via `ToolExecutionBoundary` or `RequestEngine`, safety and scope gates, structured argument generation, output parsing/normalization, persistence, and attack-surface graph integration.

---

## 2. Comprehensive Tool Audit Matrix

| Tool | Intended Purpose | Adapter | Execution Path | Safety Gate | Output Parsed | Snapshot Integration | Real Execution | Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Subfinder** | Passive subdomain enumeration | `SubfinderProvider` (`providers.py:138`) | `UnifiedReconOrchestrator` & `ReconAgent` | `ToolExecutionBoundary` + ScopeValidator | YES | YES | NO (binary absent) | `EXECUTION_FAILED` (Binary not in PATH) |
| **Sublist3r** | Legacy subdomain scraper | Formal stub (`providers.py:521`) | Blocked in orchestrator | Hardcoded `NOT_IMPLEMENTED` | NO | NO | NO | `NOT_IMPLEMENTED` (coverage duplicated) |
| **Amass** | Passive asset / OSINT discovery | `AmassProvider` (`providers.py:331`) | `UnifiedReconOrchestrator` & `ReconAgent` | `ToolExecutionBoundary` + ScopeValidator | YES | YES | NO (binary absent) | `EXECUTION_FAILED` (Binary not in PATH) |
| **crt.sh / CT** | Passive certificate transparency logs | `CRTShProvider` (`crtsh_provider.py`) | `UnifiedReconOrchestrator` (`providers.py:602`) | `RequestEngine` + ScopeValidator | YES | YES | Gated | `BLOCKED_AUTHORIZATION` / `LIVE_VALIDATED` |
| **Wayback** | Historical endpoint & URL discovery | `WaybackProvider` (`wayback_provider.py`) | `ReconAgent` & Passive Discovery | `RequestEngine` (Target untouched) | YES | YES | Gated | `BLOCKED_AUTHORIZATION` / `LIVE_VALIDATED` |
| **GAU** | Historical URL collection | `ALLOWED_TOOLS["gau"]` | `ReconAgent:440` | `ToolExecutionBoundary` + ScopeValidator | YES | YES | NO (binary absent) | `EXECUTION_FAILED` (Binary not in PATH) |
| **DNS Recon** | Controlled DNS record resolution | `DNSProviderAdapter` (`providers.py:761`) | `UnifiedReconOrchestrator` | dnspython bounded query budget (50 max) | YES | YES | Gated | `BLOCKED_AUTHORIZATION` / `LIVE_VALIDATED` |
| **HTTP Probe** | Read-only HTTP surface probing | `HttpProbeProvider` (`providers.py:935`) | `UnifiedReconOrchestrator` | `RequestEngine` (GET/HEAD/OPTIONS, <=2 rps, <=10 reqs) | YES | YES | Gated | `BLOCKED_AUTHORIZATION` / `LIVE_VALIDATED` |
| **WhatWeb** | Web technology fingerprinting | `ALLOWED_TOOLS["whatweb"]` | `ReconAgent:505` | `ToolExecutionBoundary` + ScopeValidator | YES | YES | NO (binary absent) | `EXECUTION_FAILED` (Binary not in PATH) |
| **Nmap** | Port & service discovery | `ALLOWED_TOOLS["nmap"]` | `ReconAgent:526` | `ToolExecutionBoundary` + explicit port policy | YES | YES | NO (policy + binary) | `BLOCKED_POLICY` (Port scan unauthorized) |
| **Gobuster** | Content / directory enumeration | `ALLOWED_TOOLS["gobuster"]` | `ReconAgent:547` | `ToolExecutionBoundary` + explicit dir policy | YES | YES | NO (policy + binary) | `BLOCKED_POLICY` (Brute force unauthorized) |
| **Nuclei** | Vulnerability template scanning | `ALLOWED_TOOLS["nuclei"]` | None (Recon pipeline only) | Recon-only safety gate | NO | NO | NO | `NOT_SELECTED_RECON_ONLY` |
| **Dalfox** | XSS vulnerability validation | `ALLOWED_TOOLS["dalfox"]` | None (Recon pipeline only) | Recon-only safety gate | NO | NO | NO | `NOT_SELECTED_RECON_ONLY` |

---

## 3. Tool-by-Tool Detailed Findings (15 Invariant Checklist)

### 1. Subfinder
1. **Executable/tool actually integrated:** Defined in `ToolExecutionBoundary.ALLOWED_TOOLS["subfinder"]`. However, `subfinder` binary is **not** present in system PATH (`shutil.which("subfinder")` returns `None`).
2. **Adapter exists:** Yes, `SubfinderProvider` in `backend/recon/providers.py:138`.
3. **Execution path from ReconOrchestrator:** Yes, initialized in `UnifiedReconOrchestrator.__init__` and executed in `execute_recon`.
4. **Execution passes through ToolExecutionBoundary:** Yes, via `self.tool_boundary.execute(req)`.
5. **Authorization enforced:** Yes, requires `context.is_live_allowed()` which checks `authorization_record_id` and `operator_confirmed`.
6. **Scope enforced:** Yes, discovered subdomains are individually validated against `scope_validator.validate_target()`.
7. **Arguments generated safely:** Yes, structured list `["-d", domain, "-silent"]` without shell interpolation.
8. **Output captured:** Yes, `stdout`, `stderr`, and SHA-256 hashes recorded.
9. **Output parsed:** Yes, split into lines and cleaned.
10. **Output normalized:** Yes, RFC-compliant domain normalization via `normalize_domain()`.
11. **Output persisted:** Yes, stored as `NormalizedReconAsset` instances with evidence hashes.
12. **Output contributes to ReconSnapshot:** Yes, included in `CanonicalReconSnapshot.normalized_assets`.
13. **Output contributes to attack-surface graph:** Yes, populated into `AttackSurfaceGraphEngine`.
14. **Automated test proving integration:** Yes (`backend/tests/test_recon_providers.py`).
15. **Has tool actually executed against real authorized target:** No, host environment lacks the binary. Invocation yields `ToolExecutionStatus.BINARY_NOT_FOUND` / `LIVE_FAILED`.

### 2. Sublist3r
1. **Executable/tool actually integrated:** No. Sublist3r is intentionally uninstalled and deprecated.
2. **Adapter exists:** Formal classification adapter `Sublist3rProvider` in `backend/recon/providers.py:521`.
3. **Execution path from ReconOrchestrator:** Yes, registered in provider map.
4. **Execution passes through ToolExecutionBoundary:** No subprocess is spawned.
5. **Authorization enforced:** Yes, preflight gate.
6. **Scope enforced:** Yes, preflight gate.
7. **Arguments generated safely:** N/A (no execution).
8. **Output captured:** N/A.
9. **Output parsed:** N/A.
10. **Output normalized:** N/A.
11. **Output persisted:** N/A.
12. **Output contributes to ReconSnapshot:** Returns status `NOT_IMPLEMENTED`.
13. **Output contributes to attack-surface graph:** No.
14. **Automated test proving integration:** Yes (`test_sublist3r_classified_not_implemented`).
15. **Has tool actually executed against real authorized target:** No.
- **Formal Disposition:** `NOT_IMPLEMENTED`. Sublist3r is an unmaintained Python 2/3 legacy scraping tool. Its search engine scrapers are fragile and blocked by rate limits, yielding data that is completely duplicated and surpassed by Subfinder, Amass, and Certificate Transparency.

### 3. Amass
1. **Executable/tool actually integrated:** In `ALLOWED_TOOLS["amass"]`. Binary not installed in PATH (`shutil.which` returns `None`).
2. **Adapter exists:** Yes, `AmassProvider` in `backend/recon/providers.py:331`.
3. **Execution path from ReconOrchestrator:** Yes, in `UnifiedReconOrchestrator`.
4. **Execution passes through ToolExecutionBoundary:** Yes (`self.tool_boundary.execute`).
5. **Authorization enforced:** Yes (`context.is_live_allowed()`).
6. **Scope enforced:** Yes, per-asset `scope_validator.validate_target()`.
7. **Arguments generated safely:** Yes (`["enum", "-passive", "-d", domain]`).
8. **Output captured:** Yes.
9. **Output parsed:** Yes.
10. **Output normalized:** Yes (`normalize_domain`).
11. **Output persisted:** Yes (`NormalizedReconAsset`).
12. **Output contributes to ReconSnapshot:** Yes.
13. **Output contributes to attack-surface graph:** Yes.
14. **Automated test proving integration:** Yes (`test_recon_providers.py`).
15. **Has tool actually executed against real authorized target:** No, binary absent on host.

### 4. Certificate Transparency (crt.sh)
1. **Executable/tool actually integrated:** Yes, pure Python network client (`CRTShProvider`) querying crt.sh JSON endpoint via `RequestEngine`. No CLI binary required.
2. **Adapter exists:** Yes, `CertificateTransparencyProvider` in `backend/recon/providers.py:602` and `CRTShProvider` in `backend/services/discovery/crtsh_provider.py`.
3. **Execution path from ReconOrchestrator:** Yes, in `UnifiedReconOrchestrator`.
4. **Execution passes through ToolExecutionBoundary:** Operates through central network boundary `RequestEngine` with `ScopeValidator`, timeout (20s), and rate limiting (1 rps).
5. **Authorization enforced:** Yes (`context.is_live_allowed()`).
6. **Scope enforced:** Yes, discovered domains checked against target domain and scope rules.
7. **Arguments generated safely:** Yes, URL formatted with sanitized domain.
8. **Output captured:** Yes, HTTP response body, status, headers, and SHA-256 evidence.
9. **Output parsed:** Yes, parses JSON array and extracts `name_value` and `common_name`.
10. **Output normalized:** Yes, RFC-compliant domain normalization and deduplication.
11. **Output persisted:** Yes, stored in evidence vault with evidence hash.
12. **Output contributes to ReconSnapshot:** Yes (`NormalizedReconAsset`).
13. **Output contributes to attack-surface graph:** Yes.
14. **Automated test proving integration:** Yes (`test_passive_providers.py`, `test_recon_providers.py`).
15. **Has tool actually executed against real authorized target:** Dependent on exact target authorization gate for `https://www.mitacsc.ac.in`.

### 5. Wayback (Archive.org CDX API)
1. **Executable/tool actually integrated:** Yes, `WaybackProvider` in `backend/services/discovery/wayback_provider.py` querying Archive.org CDX API via `RequestEngine`. (CLI `waybackurls` in `ALLOWED_TOOLS` is not installed).
2. **Adapter exists:** Yes, `WaybackProvider`.
3. **Execution path from ReconOrchestrator:** Yes, available for passive endpoint discovery.
4. **Execution passes through ToolExecutionBoundary:** Uses `RequestEngine` network boundary.
5. **Authorization enforced:** Yes.
6. **Scope enforced:** Yes, historical URLs filtered and validated; target server is never contacted.
7. **Arguments generated safely:** Yes, clean query string to `web.archive.org/cdx/search/cdx`.
8. **Output captured:** Yes, CDX JSON response and SHA-256 evidence hash.
9. **Output parsed:** Yes, original URLs extracted from rows.
10. **Output normalized:** Yes, URL canonicalization and parameter sorting.
11. **Output persisted:** Yes, with source `SRC_WAYBACK` and evidence ID.
12. **Output contributes to ReconSnapshot:** Yes.
13. **Output contributes to attack-surface graph:** Yes.
14. **Automated test proving integration:** Yes (`test_passive_providers.py`).
15. **Has tool actually executed against real authorized target:** Gated by authorization check.

### 6. GAU (GetAllUrls)
1. **Executable/tool actually integrated:** In `ALLOWED_TOOLS["gau"]`. Binary not installed in PATH.
2. **Adapter exists:** Called in `backend/agents/recon_agent.py:440`.
3. **Execution path from ReconOrchestrator:** Present in `ReconAgent`.
4. **Execution passes through ToolExecutionBoundary:** Yes (`ToolExecutionRequest(tool_name="gau", ...)`).
5. **Authorization enforced:** Yes.
6. **Scope enforced:** Yes.
7. **Arguments generated safely:** Yes (`["--subs", domain]`).
8. **Output captured:** Yes.
9. **Output parsed:** Yes (`splitlines()`).
10. **Output normalized:** Yes (`canonicalize_url`).
11. **Output persisted:** Yes.
12. **Output contributes to ReconSnapshot:** Yes.
13. **Output contributes to attack-surface graph:** Yes.
14. **Automated test proving integration:** Yes (`test_recon_agent.py`).
15. **Has tool actually executed against real authorized target:** No, binary absent on host.

### 7. DNS Enumeration
1. **Executable/tool actually integrated:** Yes, native Python `dnspython` library (`dns.resolver`).
2. **Adapter exists:** Yes, `DNSProviderAdapter` in `backend/recon/providers.py:761`.
3. **Execution path from ReconOrchestrator:** Yes, in `UnifiedReconOrchestrator`.
4. **Execution passes through ToolExecutionBoundary:** Controlled resolver abstraction bounded to 5s timeout, 10s lifetime, max 50 queries.
5. **Authorization enforced:** Yes (`context.is_live_allowed()`).
6. **Scope enforced:** Yes, only queries authorized target domain.
7. **Arguments generated safely:** Yes, restricted query types (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `SOA`).
8. **Output captured:** Yes, dictionary of record types and values.
9. **Output parsed:** Yes, records categorized as `IP_ADDRESS` or `DNS_RECORD`.
10. **Output normalized:** Yes, format `{domain}:{rec_type}:{value}`.
11. **Output persisted:** Yes, SHA-256 evidence hash.
12. **Output contributes to ReconSnapshot:** Yes.
13. **Output contributes to attack-surface graph:** Yes.
14. **Automated test proving integration:** Yes (`test_recon_providers.py`).
15. **Has tool actually executed against real authorized target:** Gated by authorization check.

### 8. HTTP/HTTPS Probing
1. **Executable/tool actually integrated:** Yes, native `RequestEngine` + `HttpProbeEngine`.
2. **Adapter exists:** Yes, `HttpProbeProvider` in `backend/recon/providers.py:935`.
3. **Execution path from ReconOrchestrator:** Yes, in `UnifiedReconOrchestrator`.
4. **Execution passes through ToolExecutionBoundary:** Operates through central `RequestEngine` boundary with `ScopeValidator` and anti-SSRF `validate_destination_safety`.
5. **Authorization enforced:** Yes (`context.is_live_allowed()`).
6. **Scope enforced:** Yes, strictly checks in-scope URL and destination safety.
7. **Arguments generated safely:** Yes, GET/HEAD/OPTIONS only, rate limit <= 2.0 rps, max requests <= 10.
8. **Output captured:** Yes, HTTP status, server header, title, redirect chain, evidence hash.
9. **Output parsed:** Yes, `HttpProbeResult`.
10. **Output normalized:** Yes, `NormalizedReconAsset` (`SERVICE` / `WEB_APPLICATION`).
11. **Output persisted:** Yes, SHA-256 evidence hashes.
12. **Output contributes to ReconSnapshot:** Yes.
13. **Output contributes to attack-surface graph:** Yes (`AttackSurfaceGraphEngine.add_endpoint`).
14. **Automated test proving integration:** Yes (`test_recon_providers.py`, `test_phase5_http_probing.py`).
15. **Has tool actually executed against real authorized target:** Gated by authorization check.

### 9. WhatWeb
1. **Executable/tool actually integrated:** Defined in `ALLOWED_TOOLS["whatweb"]`. Binary not installed in PATH. (AihaX has native passive `TechnologyFingerprintProvider` which analyzes HTTP headers/body).
2. **Adapter exists:** External CLI adapter in `ReconAgent:505`; native adapter in `providers.py:1121`.
3. **Execution path from ReconOrchestrator:** Native detector in `UnifiedReconOrchestrator`; CLI in `ReconAgent`.
4. **Execution passes through ToolExecutionBoundary:** Yes for CLI (`ToolExecutionRequest(tool_name="whatweb", args=["--log-json", "-", target_url])`).
5. **Authorization enforced:** Yes.
6. **Scope enforced:** Yes.
7. **Arguments generated safely:** Yes (`["--log-json", "-", target_url]`).
8. **Output captured:** Yes.
9. **Output parsed:** Yes (`_parse_whatweb_output`).
10. **Output normalized:** Yes (`TechnologyObservation`).
11. **Output persisted:** Yes.
12. **Output contributes to ReconSnapshot:** Yes.
13. **Output contributes to attack-surface graph:** Yes (`TECHNOLOGY` nodes).
14. **Automated test proving integration:** Yes (`test_recon_agent.py`).
15. **Has tool actually executed against real authorized target:** No, binary absent on host.

### 10. Nmap
1. **Executable/tool actually integrated:** Defined in `ALLOWED_TOOLS["nmap"]`. Binary not installed in PATH.
2. **Adapter exists:** In `ReconAgent:526`.
3. **Execution path from ReconOrchestrator:** Present in `ReconAgent`.
4. **Execution passes through ToolExecutionBoundary:** Yes (`ToolExecutionRequest(tool_name="nmap", args=["-sT", "-T4", "--open", domain])`).
5. **Authorization enforced:** Yes, requires `config.enable_port_scan` AND `config.authorization_confirmed`.
6. **Scope enforced:** Yes.
7. **Arguments generated safely:** Yes, bounded flags only (`-sT`, `-T4`, `--open`).
8. **Output captured:** Yes.
9. **Output parsed:** Yes (`_parse_nmap_output`).
10. **Output normalized:** Yes (open ports and services).
11. **Output persisted:** Yes.
12. **Output contributes to ReconSnapshot:** Yes.
13. **Output contributes to attack-surface graph:** Yes (`SERVICE` nodes).
14. **Automated test proving integration:** Yes (`test_recon_agent.py`).
15. **Has tool actually executed against real authorized target:** No. Port scanning is not authorized in scope policies (`BLOCKED_POLICY`), and binary is not installed on host.

### 11. Gobuster
1. **Executable/tool actually integrated:** Defined in `ALLOWED_TOOLS["gobuster"]`. Binary not installed in PATH.
2. **Adapter exists:** In `ReconAgent:547`.
3. **Execution path from ReconOrchestrator:** Present in `ReconAgent`.
4. **Execution passes through ToolExecutionBoundary:** Yes (`ToolExecutionRequest(tool_name="gobuster", args=["dir", "-u", target_url, "-q"])`).
5. **Authorization enforced:** Yes, requires `config.enable_directory_discovery` AND `config.authorization_confirmed`.
6. **Scope enforced:** Yes.
7. **Arguments generated safely:** Yes (`["dir", "-u", target_url, "-q"]`).
8. **Output captured:** Yes.
9. **Output parsed:** Yes.
10. **Output normalized:** Yes (`canonicalize_url`).
11. **Output persisted:** Yes.
12. **Output contributes to ReconSnapshot:** Yes (`DIRECTORY` observations).
13. **Output contributes to attack-surface graph:** Yes.
14. **Automated test proving integration:** Yes (`test_recon_agent.py`).
15. **Has tool actually executed against real authorized target:** No. Brute-force directory discovery is disallowed without explicit authorization (`BLOCKED_POLICY`), and binary is not installed on host.

### 12. Nuclei
1. **Executable/tool actually integrated:** Defined in `ALLOWED_TOOLS["nuclei"]`. Binary not installed on host.
2. **Adapter exists:** Boundary profile `VULNERABILITY_SCANNING`.
3. **Execution path from ReconOrchestrator:** Excluded from reconnaissance pipeline.
4. **Execution passes through ToolExecutionBoundary:** Profile supported.
5. **Authorization enforced:** Yes.
6. **Scope enforced:** Yes.
7. **Arguments generated safely:** Allowed flags only.
8. **Output captured:** Bounded by profile.
9. **Output parsed:** Yes (JSON lines).
10. **Output normalized:** Yes (Findings model).
11. **Output persisted:** Yes (Findings table).
12. **Output contributes to ReconSnapshot:** No (vulnerability scanner, not recon asset model).
13. **Output contributes to attack-surface graph:** No.
14. **Automated test proving integration:** Yes (`test_tool_execution_boundary.py`).
15. **Has tool actually executed against real authorized target:** No.
- **Formal Disposition:** `NOT_SELECTED_RECON_ONLY`. Nuclei is a vulnerability scanner; Phase 25 is strictly bounded to reconnaissance validation.

### 13. Dalfox
1. **Executable/tool actually integrated:** Defined in `ALLOWED_TOOLS["dalfox"]`. Binary not installed on host.
2. **Adapter exists:** Boundary profile `XSS_VALIDATION`. Autonomous execution deferred in `vuln_agent.py`.
3. **Execution path from ReconOrchestrator:** None (active XSS exploit validation tool).
4. **Execution passes through ToolExecutionBoundary:** Profile supported.
5. **Authorization enforced:** Yes.
6. **Scope enforced:** Yes.
7. **Arguments generated safely:** Bounded flags.
8. **Output captured:** Bounded.
9. **Output parsed:** Yes.
10. **Output normalized:** Yes.
11. **Output persisted:** Yes.
12. **Output contributes to ReconSnapshot:** No.
13. **Output contributes to attack-surface graph:** No.
14. **Automated test proving integration:** Yes (`test_tool_execution_boundary.py`).
15. **Has tool actually executed against real authorized target:** No.
- **Formal Disposition:** `NOT_SELECTED_RECON_ONLY`. Dalfox is an active fuzzer/exploit tool; strictly prohibited during recon validation.

---

## 4. Authorization & Scope Gate Status for `https://www.mitacsc.ac.in`

An inspection of `db/aihax.db` shows:
- Existing active authorization records and campaigns exist for the apex target: `https://mitacsc.ac.in/` (e.g. Campaign ID `17a81c94-cb58-4381-866f-9624e21a1cad`, Authorization Record ID `78cd593d-7ac8-4e18-9baa-98f4e4f93571`, Status `ACTIVE`, valid until `2026-10-02`).
- The program scope in `program_scopes` specifies: `in_scope_assets = ["https://mitacsc.ac.in/"]`.
- When evaluated with `ScopeValidator(in_scope_assets=["https://mitacsc.ac.in/"])`, the concrete target `https://www.mitacsc.ac.in` returns:
  ```python
  ScopeDecision(allowed=False, status=DENIED_BY_DEFAULT, reason="Host 'www.mitacsc.ac.in' does not match any authorized in-scope rules (Default Deny)")
  ```
- No authorization record explicitly lists `https://www.mitacsc.ac.in`.
- Under Section 1 Safety Invariants:
  > Require a valid AihaX authorization record for: `https://www.mitacsc.ac.in`. If the required authorization record does not exist: STOP LIVE EXECUTION. Report: `BLOCKED_AUTHORIZATION`. Do not weaken the authorization system to make the test pass.

Therefore, for the target `https://www.mitacsc.ac.in`, live execution must halt and report `BLOCKED_AUTHORIZATION` unless an explicit authorization record for `https://www.mitacsc.ac.in` is registered in the authorization system.
