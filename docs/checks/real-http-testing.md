# Real HTTP Integration & Adversarial Testbed Architecture

> **Component:** `backend/tests/test_77_checks_real_http.py`  
> **Status:** Verified (18/18 Passing over Loopback TCP Sockets)  
> **Transport:** `AiohttpTransport` via `RequestEngine`  

---

## 1. Overview & Architecture

AihaX employs a deterministic testbed architecture to validate security checks using genuine HTTP network communication over actual operating system sockets.

```
┌────────────────────────────────────────────────────────┐
│             Check Contract & Execution                 │
│         (e.g., C027_OS_Command_Injection)              │
└───────────────────────────┬────────────────────────────┘
                            │ RequestSpec (canary payload)
                            ▼
┌────────────────────────────────────────────────────────┐
│             Centralized RequestEngine                  │
│       • ScopeValidator Check (127.0.0.1 In-Scope)      │
│       • RateLimiter & Timeout Enforcement              │
│       • Secret Redaction & Evidence Recording          │
└───────────────────────────┬────────────────────────────┘
                            │ HTTP TCP Request
                            ▼
┌────────────────────────────────────────────────────────┐
│         Live Aiohttp Testbed Application               │
│          (Local In-Process TCP Server)                 │
│       • Vulnerable Endpoints (/vulnerable/*)           │
│       • Secure Baseline (/secure/*)                    │
│       • Deceptive / FP Endpoints (/deceptive/*)        │
└───────────────────────────┬────────────────────────────┘
                            │ Real HTTP Response
                            ▼
┌────────────────────────────────────────────────────────┐
│               CheckResult (CANDIDATE)                  │
└───────────────────────────┬────────────────────────────┘
                            │ Deterministic Evidence
                            ▼
┌────────────────────────────────────────────────────────┐
│             VerificationEngine Strategy                │
│    (GenericReproducibility, SensitiveFile, etc.)       │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
            ┌───────────────────────────────┐
            │   VERIFIED / FALSE_POSITIVE   │
            └───────────────────────────────┘
```

---

## 2. Testbed Test Categories

### A. Positive Vulnerability Replay
Endpoints intentionally configured to demonstrate realistic security vulnerabilities under non-destructive conditions:

| Endpoint | Target Check | Payload / Condition | Real Observed Response | Verdict |
|---|---|---|---|---|
| `/.env` | `C003_Sensitive_Files_Exposure` | `GET /.env` | `DB_PASSWORD=supersecret_pass123` | **VERIFIED** |
| `/vulnerable/c004_cors` | `C004_CORS_Misconfiguration` | `Origin: https://evil.com` | `Access-Control-Allow-Origin: https://evil.com` | **VERIFIED** |
| `/actuator/health` | `C009_Exposed_Admin_Interface` | `GET /actuator/health` | `{"status": "UP", "_links": ...}` | **VERIFIED** |
| `/vulnerable/c012_auth_bypass` | `C012_Auth_Bypass_Indicators` | `X-Original-URL: /admin` | `200 OK (Welcome Admin!)` | **VERIFIED** |
| `/vulnerable/c020_jwt` | `C020_JWT_Algorithm_Weakness` | `Bearer <alg: none token>` | `200 OK (Admin access granted)` | **VERIFIED** |
| `/vulnerable/c023_sqli` | `C023_SQL_Injection` | `id=1'` | `MySQL syntax error near '' at line 1` | **VERIFIED** |
| `/vulnerable/c027_os_cmdi` | `C027_OS_Command_Injection` | `ip=127.0.0.1; expr 31330 + 7 ;` | `31337 in response body` | **VERIFIED** |
| `/vulnerable/c028_ssti` | `C028_SSTI` | `name={{31330+7}}` | `Hello 31337! Welcome` | **VERIFIED** |
| `/vulnerable/c031_traversal` | `C031_Path_Traversal` | `file=../../../../etc/passwd` | `root:x:0:0:root:/root` | **VERIFIED** |
| `/vulnerable/c037_xss` | `C037_Reflected_XSS` | `q=<aihax-xss-canary-777>` | `<aihax-xss-canary-777> in text/html` | **VERIFIED** |
| `/vulnerable/c057_keys` | `C057_Exposed_API_Keys` | `GET /vulnerable/c057_keys` | `AKIAIOSFODNN7EXAMPLE` (Redacted in proof) | **VERIFIED** |
| `/vulnerable/c067_idor` | `C067_IDOR_Numeric_IDs` | `user_id=1002` | `{"email": "victim@corp", "billing": "$9,400"}` | **VERIFIED** |
| `/vulnerable/c070_mass_assignment` | `C070_Mass_Assignment` | `{"is_admin": true, "role": "admin"}` | `{"is_admin": true, "role": "admin"}` in JSON | **VERIFIED** |

---

### B. Negative Controls (Secure Targets)
Target `/secure/app` implements all modern defense-in-depth security headers and proper input sanitization:
* `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
* `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`
* `X-Frame-Options: DENY`
* `X-Content-Type-Options: nosniff`
* `Access-Control-Allow-Origin: https://trusted-site.com`

**Result:** `0` candidate findings and `0` verified findings produced across all executed checks.

---

### C. Adversarial Deceptive / False-Positive Tests

1. **Generic 500 Internal Server Error:**
   * **Endpoint:** `/deceptive/sqli_500` (Returns HTTP 500 without database error text).
   * **Defense:** `C023_SQL_Injection` checks strictly for database vendor syntax signatures, rejecting generic HTTP 500 responses.
   * **Result:** `None` (0 findings).

2. **Properly HTML-Encoded XSS Reflection:**
   * **Endpoint:** `/deceptive/xss_encoded?q=<tag>` (Returns `&lt;tag&gt;` in HTML body).
   * **Defense:** `C037_Reflected_XSS` verifies that the raw tag is unencoded and ensures that encoded representations do NOT trigger an alert.
   * **Result:** `None` (0 findings).

3. **Soft-404 Sensitive File Request:**
   * **Endpoint:** `/deceptive/soft_404` (Returns HTTP 200 with generic HTML error message).
   * **Defense:** `SensitiveFileExposureStrategy` checks for generic HTML structures and absence of valid sensitive tokens, categorizing the candidate finding as `FALSE_POSITIVE`.
   * **Result:** `VerificationStatus.FALSE_POSITIVE`.

4. **Standard Admin Login Page:**
   * **Endpoint:** `/admin/` (Returns HTTP 200 with standard username/password login form).
   * **Defense:** `C009_Exposed_Admin_Interface` distinguishes between protected login forms requiring authentication and unauthenticated administrative panels/metrics (`/actuator`), avoiding false reports of admin console breaches.
   * **Result:** Non-elevated fallback handling / unauthenticated panel prioritized.
