# Bug Bounty Platform — Phase 1 Code Audit & Architecture Review

**Date:** 2026-08-20  
**Phase:** Phase 1 (Scope + Target Foundation)  
**Status:** Audit Complete  

---

## 1. Existing Target-Related Models
- **`Scan` (`backend/models/database.py`)**:
  - Contains `id`, `target_url`, `created_at`, `completed_at`, `status`, `scan_depth`, `scan_mode`, `threads`, `waf_bypass`, `stealth_mode`, `industry`, `tech_stack`, `total_findings`, `risk_score`, `report_path`, `report_format`, `schedule_id`, `admin_mode`, `user_id`, `user_email`.
  - Relationship to `ScanConfig`, `Finding`, `AgentLog`, `ExploitChain`.
- **`WatchSchedule` (`backend/models/database.py`)**:
  - Contains `target_url`, `schedule_type`, `last_run`, `next_run`, `scan_payload`, `scope_notes`, etc.
- **`Finding` (`backend/models/database.py`)**:
  - Tracks `affected_url`, `affected_param`, `payload`, `proof_request`, `proof_response`, `verdict`, `confidence`, `false_positive`.

*Gap:* Currently, scans are tied only to a single `target_url` string. There is no first-class `Program` or `Scope` entity allowing multiple in-scope/out-of-scope assets, wildcard domain rules, port ranges, path exclusions, or scheme restrictions.

---

## 2. Existing Scan Configuration
- **`ScanConfig` Schema (`backend/models/schemas.py`)**:
  - Accepts `target_url`, `industry`, `primary_creds`, `secondary_creds`, `email_creds`, `two_fa_type`, `two_fa_config`, `api_auth`, `scan_depth` (`light`, `normal`, `deep`), `threads` (1-20), `waf_bypass`, `stealth_mode`, `authorization_confirmed`, `scope_notes`, `scan_mode` (`standard`, `bugbounty`, `compliance`, `watch`), `report_format`, `admin_mode`.
- **`ScanConfig` ORM Model (`backend/models/database.py`)**:
  - Stores encrypted credentials, `authorization_confirmed` (Boolean), `authorization_notes` (Text).
- **Scan Initialization (`backend/routers/scan.py`)**:
  - Parses `ScanConfig`, persists to DB, and triggers `run_scan_pipeline`.

*Gap:* Scan modes need normalization for bug bounty workflows (`PASSIVE`, `SAFE`, `STANDARD`). Rate limiting is currently not parameterized on a per-scan basis (`requests_per_second`, `max_concurrency`).

---

## 3. Existing Scope Functionality
- **`ScopeAgent` (`backend/agents/scope_agent.py`)**:
  - Currently checks only if `authorization_confirmed` is True and `scope_notes` is non-empty.
  - Does **not** perform granular asset matching, subdomain validation, wildcard checking, exclusion overrides, port validation, or path prefix validation.
- **`validate_target_url` (`backend/core/url_validator.py`)**:
  - Blocks SSRF/private networks (RFC 1918, loopbacks, `.internal`, `.local`, metadata endpoints).
  - Validates scheme (`http`/`https`) and resolves DNS to prevent localhost bypasses.

*Gap:* No dedicated `ScopeValidator` exists to determine `IN_SCOPE`, `OUT_OF_SCOPE`, or `INVALID` for hosts, URLs, ports, or paths against a program's scope definition.

---

## 4. Existing Rate Limiting
- **`backend/core/rate_limit.py`**:
  - Implements sliding-window rate limiting for scan launches (`check_scan_rate_limit`: 5 scans/minute).
  - Implements API request rate limiting (`public` vs `authenticated`) and auth brute-force protection with exponential backoff.

*Gap:* No per-scan rate limit configuration (`requests_per_second`, `max_concurrency`) modeled or enforced per target asset.

---

## 5. Existing Request / Network Layer
- Checks in `backend/agents/checks/` and agents (`ReconAgent`, `VulnAgent`) use `aiohttp`, `asyncio.subprocess` (nmap/subfinder/whatweb), and socket connections.
- Currently, individual checks execute against `target_url` without querying a centralized scope validator before sending packets.

*Gap:* Need a reusable, deterministic `ScopeValidator` that can gate any URL or host before network calls occur.

---

## 6. Existing Frontend Configuration
- **`NewScan.jsx` (`frontend/src/pages/NewScan.jsx`)**:
  - 3-step wizard: Target Definition -> Auth & Tuning -> Authorization.
  - Allows selecting `target_url`, `industry`, `scan_mode`, `report_format`, `threads`, `scan_depth`, credentials, `authorization_confirmed`, `scope_notes`.

*Gap:* Needs clean UI support for configuring Program Name, in-scope assets, out-of-scope assets, allowed/excluded ports, scan modes (`PASSIVE`, `SAFE`, `STANDARD`), rate limits, and clear visual scope tags.

---

## 7. Existing Tests
- Baseline backend test suite: **110 passed / 110 collected**.
- Baseline frontend test suite: **11 passed / 11 collected**.
- Frontend lint: **0 errors, 0 warnings**.
- Production build: **Clean**.

---

## 8. Missing Functionality (Phase 1 Scope)
1. **Scope Domain Model**:
   - `Program` (id, name, description, created_at, user_id)
   - `ProgramScope` / `ScopeConfig` (program_id, in_scope_assets, out_of_scope_assets, allowed_ports, excluded_ports, allowed_schemes, excluded_paths, scope_notes)
   - Scan config extensions: `program_id`, `scan_mode` (`PASSIVE`, `SAFE`, `STANDARD`), `rate_limit` (`requests_per_second`, `max_concurrency`), `authorization_confirmed`.
2. **Scope Normalization Engine**:
   - Canonical normalization of domains, subdomains, wildcards (`*.example.com`), CIDRs/IPs, and path prefixes (`/api/v1/*`).
   - Case-folding, scheme extraction, trailing slash normalization, userinfo stripping prevention.
3. **Deterministic `ScopeValidator`**:
   - Methods: `is_host_in_scope`, `is_url_in_scope`, `is_port_in_scope`, `is_asset_in_scope`.
   - Structured results: `ScopeDecision(allowed: bool, status: ScopeStatus, reason: str, asset: str)`.
   - Precedence: `EXPLICIT EXCLUSION > EXPLICIT INCLUSION > WILDCARD INCLUSION > DEFAULT DENY`.
   - Safe wildcard isolation: `*.example.com` matches `sub.example.com`, but rejects `example.com.evil.com`, `evil-example.com`, and does not implicitly include the apex `example.com` unless specified.
   - Userinfo defense: `https://example.com@evil.com` correctly parses host as `evil.com` and is rejected.
4. **Backend REST APIs**:
   - Program & Scope CRUD endpoints (`/api/programs`, `/api/programs/{id}/scope`).
   - Target Scope Validation endpoint (`/api/programs/{id}/validate-target`).
   - Extended `/api/scan/start` validation to enforce `ScopeValidator` and `authorization_confirmed`.
5. **Database Migration**:
   - Transactional migration (version 13) to create `programs` and `program_scopes` tables and link `scans.program_id`.
6. **Comprehensive Security & Regression Test Suite**:
   - 20+ specific scope attack scenarios, normalization tests, and pipeline regression checks.

---

## 9. Recommended Minimal Changes
- Create `backend/core/scope_validator.py` containing normalization logic and `ScopeValidator`.
- Create `backend/models/scope_models.py` (or extend `backend/models/database.py` and `backend/models/schemas.py`) with `Program` and `ProgramScope`.
- Add migration `013_bug_bounty_programs_and_scope` in `backend/models/migrations.py`.
- Create `/api/programs` router in `backend/routers/programs.py` and register in `backend/main.py`.
- Update `backend/agents/scope_agent.py` to use `ScopeValidator` for gating pipeline execution.
- Update `frontend/src/pages/NewScan.jsx` to support Program, In-Scope, Out-of-Scope, Ports, Rate Limits, and Authorization confirmation.
- Add test suites `backend/tests/test_scope_validator.py` and `backend/tests/test_programs_api.py`.
