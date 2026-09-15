# Bug Bounty Platform — Phase 2 Network & Request Architecture Audit

**Date:** 2026-08-21  
**Phase:** Phase 2 (Central Request + Evidence Engine)  
**Status:** Audit Complete  

---

## 1. Existing HTTP Clients & Network Libraries
- **`aiohttp`**:
  - Found in `backend/agents/vuln_agent.py` in legacy helper methods (`_test_sensitive_data`, `_test_cors`, `_test_clickjacking`, `_test_graphql`, `_test_idor`).
  - Listed in `backend/requirements.txt`.
- **`requests`**:
  - Used in `backend/core/auth.py` for Google OAuth token verification (`https://oauth2.googleapis.com/tokeninfo`).
  - Used in `backend/services/watch_scheduler.py` for outbound notification webhooks (`schedule.alert_webhook`).
- **`urllib.parse`**:
  - Used for URL splitting, scheme extraction, hostname isolation, and path normalization in `backend/core/url_validator.py` and `backend/core/scope_validator.py`.
- **`socket`**:
  - Used in `backend/core/url_validator.py` to resolve DNS (`socket.getaddrinfo`) and detect loopback/private IPs.
  - Used in `backend/core/auth.py` to detect local Docker subnet IP addresses.

---

## 2. Existing Network Helpers & Abstractions
- There is currently **no centralized HTTP request engine** or shared request wrapper across the platform.
- Individual agents and checks either:
  1. Construct their own `aiohttp.ClientSession()` on the fly with ad-hoc timeouts,
  2. Spawn subprocess binaries (`nmap`, `whatweb`, `subfinder`), or
  3. Return mock stub contracts (e.g. `c001_open_port_80`, `c002_missing_security_headers`).

---

## 3. Existing Direct Network Calls by Component

| Component | Network Mechanism | Target / Destination | Purpose |
| :--- | :--- | :--- | :--- |
| `backend/agents/vuln_agent.py` | `aiohttp.ClientSession` (ad-hoc) | `target_url` | Legacy vulnerability check methods |
| `backend/agents/recon_agent.py` | `asyncio.subprocess` (nmap, subfinder, whatweb, gau) | Target domain / host | Port scan, subdomain recon, tech detection |
| `backend/core/auth.py` | `requests.get` | `oauth2.googleapis.com` | Google OIDC Token verification (Infrastructure) |
| `backend/services/watch_scheduler.py` | `requests.post` | User Webhook URL | Outbound notifications (Infrastructure) |
| `backend/core/url_validator.py` | `socket.getaddrinfo` | Target hostname | SSRF / private IP detection |

---

## 4. Existing Timeout Configuration
- `aiohttp` calls in `vuln_agent.py` use hardcoded `aiohttp.ClientTimeout(total=10)`.
- `requests.get` in `auth.py` and `watch_scheduler.py` uses `timeout=10`.
- Subprocesses in `recon_agent.py` use 120s–300s timeouts.
- **Gap:** No granular separation between connection timeout, socket read timeout, and total request timeout. No safeguards preventing callers from specifying infinite or excessive timeouts.

---

## 5. Existing Retry Behavior
- `backend/services/orchestrator.py` contains `_run_with_retry` with exponential backoff for entire Agent execution.
- **Gap:** No HTTP-level bounded retry mechanism with scope re-validation on each retry attempt.

---

## 6. Existing Redirect Behavior
- `aiohttp` default behavior follows redirects automatically up to 10 hops by default.
- **Critical Risk:** Automatic redirection can result in an in-scope request hopping to an out-of-scope target (e.g., `https://example.com/` returning `302 Location: https://evil.com/`).
- **Required Fix:** Default `follow_redirects = False`. If redirects are enabled, every intermediary and final hop must pass `ScopeValidator.validate_request()` before transmission.

---

## 7. Existing Proxy & Port Behavior
- No proxy support is currently configured.
- Port evaluation is supported in `ScopeValidator`, but `aiohttp` calls do not systematically validate port scopes before connecting.

---

## 8. Existing Authentication Handling
- `ScanConfig` accepts `primary_creds`, `secondary_creds`, `bearer_token`, `api_auth` (stored encrypted at rest in `ScanConfig`).
- **Gap:** No standardized `AuthenticationContext` abstraction to attach identity tokens/headers to outgoing requests and automatically redact secrets from captured evidence.

---

## 9. Existing Evidence Capture
- Checks return `EvidenceContract(affected_url, proof_response, confidence, proof_request)`.
- Findings in the database store `proof_request`, `proof_response`, `affected_url`, `affected_param`, `verdict`, `confidence`.
- **Gap:** No structured `RequestEvidence` DTO capturing unique request IDs (`REQ-xxxxxxxx`), full HTTP wire transcripts, duration in ms, response size, status codes, redirect chains, integrity hashes (`request_hash`, `response_hash`), or secret redaction.

---

## 10. Existing Rate Limiting
- `backend/core/rate_limit.py` implements API rate limiting (5 scans/min) and auth backoff.
- Phase 1 added `rate_limit_rps` (default 10) and `max_concurrency` (default 5) to `Scan` and `ScanConfig`.
- **Gap:** The active HTTP request layer does not currently enforce token bucket throttling or concurrency semaphores using the scan's configured rate limits.

---

## 11. Potential Paths that Could Bypass ScopeValidator
1. **Direct `aiohttp.ClientSession()` calls:** If an agent or check instantiates a raw HTTP client without passing through `ScopeValidator`.
2. **HTTP Redirect Hops:** If a server responds with 301/302/307/308 redirecting to an external or out-of-scope domain.
3. **Subprocess Network Tools:** `nmap`, `subfinder`, `whatweb` running against unvalidated hosts.
4. **Retry Loops:** If a failed request retries against a modified URL without re-validating scope.

---

## 12. Recommended Migration Path
1. Create canonical **`backend/services/request_engine.py`**:
   - `RequestSpec` (strict request definition: url, method, headers, params, body, timeouts, follow_redirects, auth_context, metadata).
   - `RequestEvidence` (structured trace: request_id, timestamp, duration_ms, request_headers, request_body, response_status, response_headers, response_body, response_size, truncated, redirect_chain, request_hash, response_hash, transport_error).
   - `AuthenticationContext` (named test identity with credentials and secret redaction rules).
   - `RequestEngine` (central orchestrator with `ScopeValidator` gating, rate-limiting token bucket, concurrency semaphore, safe redirect tracking, response truncation, and transport abstraction).
   - `TransportError` (structured network failures: `DNS_ERROR`, `CONNECTION_REFUSED`, `TIMEOUT`, `TLS_ERROR`, `REDIRECT_BLOCKED`, `SCOPE_BLOCKED`, `RESPONSE_TOO_LARGE`).
2. Integrate `RequestEngine` into check registry and agent pipeline so all future active tests go through this single interface.
3. Add full unit and integration test suite (`backend/tests/test_request_engine.py`) with 100% mocked transports.
