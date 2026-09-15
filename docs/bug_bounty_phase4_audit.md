# Bug Bounty Platform — Phase 4 Vulnerability Detector Architecture Audit

**Date:** 2026-08-21  
**Phase:** Phase 4 (Vulnerability Detector Modernization & Check Registry Integration)  
**Status:** Audit Complete  

---

## 1. Inventory of Existing Vulnerability Detectors & Checks

### 1.1 Registered Check Classes (`backend/agents/checks/`)
Currently, only 2 stub checks are registered in `CheckRegistry`:
1. **`C001_Open_Port_80`** (`backend/agents/checks/c001_open_port_80.py`)
   - Category: `RECON`
   - Severity: `INFO`
   - Current Implementation: Hardcoded URL string prefix check (`target_url.startswith("http://")`).
   - Network Mechanism: None (static stub).
   - Migration Requirement: Convert to deterministic HTTP probe via `RequestEngine` verifying whether port 80 responds to plaintext HTTP.

2. **`C002_Missing_Security_Headers`** (`backend/agents/checks/c002_missing_security_headers.py`)
   - Category: `MISCONFIG`
   - Severity: `LOW`
   - Current Implementation: Hardcoded stub returning canned proof response.
   - Network Mechanism: None (static stub).
   - Migration Requirement: Convert to live header evaluation probe via `RequestEngine`, checking response headers for `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`.

### 1.2 Unmigrated Legacy Methods in `VulnAgent` (`backend/agents/vuln_agent.py`)
`VulnAgent` contains 17 legacy vulnerability testing stubs/methods that bypassed `CheckRegistry` and used unmanaged `aiohttp.ClientSession()` or unmanaged `asyncio.subprocess`:
1. **`_test_sqli`**: Unmanaged subprocess invocation of `sqlmap`. Needs migration to discrete Check class or safe injection probe via `RequestEngine`.
2. **`_test_xss`**: Unmanaged subprocess invocation of `dalfox`. Needs migration to discrete Check class using `RequestEngine`.
3. **`_test_sensitive_data`**: Direct `aiohttp` probe against `/.env`, `/.git/config`, `/backup`, `/.htaccess`. Needs migration to `C003_Sensitive_Files_Exposure` using `RequestEngine`.
4. **`_test_cors`**: Direct `aiohttp` probe with `Origin: https://evil.com`. Needs migration to `C004_CORS_Misconfiguration` using `RequestEngine`.
5. **`_test_clickjacking`**: Direct `aiohttp` probe checking `X-Frame-Options` and CSP `frame-ancestors`. Merged/aligned with `C002_Missing_Security_Headers` / `C005_Clickjacking`.
6. **`_test_graphql`**: Direct `aiohttp` POST with introspection query. Needs migration to `C006_GraphQL_Introspection` using `RequestEngine`.
7. **`_test_path_traversal`**: Direct `aiohttp` probe for `/../../../../etc/passwd`. Needs migration to `C007_Path_Traversal` using `RequestEngine`.
8. **`_test_ssti`**: Direct `aiohttp` probe with `{{7*7}}`. Needs migration to `C008_SSTI` using `RequestEngine`.
9. **`_test_xxe`**: Direct `aiohttp` POST with XML payload. Needs migration to `C009_XXE_Injection` using `RequestEngine`.
10. **`_test_directory_listing`**: Direct `aiohttp` GET checking for `Index of /`. Needs migration to `C010_Directory_Listing` using `RequestEngine`.
11. **`_test_security_headers`**: Redundant direct `aiohttp` check. Slated for removal in favor of `C002_Missing_Security_Headers`.
12. **`_test_open_redirect`**: Direct `aiohttp` GET with `?next=https://evil.com`. Needs migration to `C011_Open_Redirect` using `RequestEngine`.
13. **`_test_ssrf`**: Direct `aiohttp` GET testing `127.0.0.1`, metadata endpoint. Needs migration to `C012_SSRF` using `RequestEngine`.
14. **`_test_idor`**: Unimplemented stub (`return None`). Needs migration to Check implementing multi-context verification contract.
15. **`_test_csrf`**: Unimplemented stub (`return None`).
16. **`_test_jwt_none`**: Unimplemented stub (`return None`).
17. **`_test_broken_auth`**: Unimplemented stub (`return None`).

---

## 2. Network & Subprocess Calls Across the Platform

| File | Mechanism | Purpose | Scope Gating | Migration Action |
| :--- | :--- | :--- | :--- | :--- |
| `backend/agents/vuln_agent.py` | Direct `aiohttp.ClientSession` | Legacy vulnerability probes | **NO** (Bypasses ScopeValidator) | Remove legacy methods; invoke only `CheckRegistry` checks via `RequestEngine`. |
| `backend/agents/vuln_agent.py` | `asyncio.create_subprocess_exec` (`sqlmap`, `dalfox`) | External CLI scanners | **NO** | Remove direct execution from `VulnAgent`. |
| `backend/agents/recon_agent.py` | `asyncio.create_subprocess_exec` (`subfinder`, `whatweb`, `gau`, `nmap`) | Subdomain, port, tech discovery | **NO** | Keep managed CLI tools in ReconAgent with sanitized input and ScopeValidator pre-checks. |
| `backend/agents/auth_agent.py` | `playwright.async_api` | Headless browser login & cookie extraction | Configured target | Ensure target URL validates through `ScopeValidator`. |
| `backend/services/watch_scheduler.py` | `requests.post` | Outbound user webhook notifications | N/A (User Webhook) | Permitted non-target system call. |
| `backend/core/auth.py` | `requests.get` | Google OAuth TokenInfo API verification | N/A (IdP API) | Permitted identity provider verification call. |

---

## 3. CheckRegistry & VerificationEngine Architecture Alignment

### 3.1 Detector Execution Model (`VulnAgent` -> `CheckRegistry` -> `RequestEngine`)
1. `VulnAgent.execute()` receives `target_url` and optional `auth_context`.
2. `VulnAgent` retrieves checks from `CheckRegistry`.
3. Each Check class instance receives `RequestEngine` (configured with `ScopeValidator` and rate limits).
4. Checks execute non-destructive probes strictly using `request_engine.execute(spec)`.
5. Upon finding an issue, the Check returns an `EvidenceContract` containing `affected_url`, `affected_param`, `payload`, `proof_request`, `proof_response`, and initial `confidence`.
6. `VulnAgent` persists candidate finding to DB with `verdict="Candidate"`, `verification_status="CANDIDATE"`.

### 3.2 Verification Model (`VerifyAgent` -> `VerificationEngine`)
1. Candidate finding enters `VerifyAgent`.
2. `VerificationEngine` looks up the corresponding `VerificationStrategy` matching `finding.vuln_type`.
3. Deterministic verification contract reproduces the finding with bounded budget (max 5 requests, 30s timeout).
4. Generates definitive verdict: `VERIFIED`, `FALSE_POSITIVE`, or `INCONCLUSIVE`.
5. Updates `Finding` in DB with reason codes and linked `evidence_ids` / `request_ids`.
6. Only findings with `verification_status="VERIFIED"` are eligible for `BugBountyReportGenerator`.
