# AihaX — 77 Checks Deep Validation Matrix

## Adversarial Engineering Audit & Classification Matrix

This document provides the exhaustive, check-by-check deep validation audit for all 77 security checks (C001–C077) implemented in the AihaX Check Registry (`backend/agents/checks/`).

---

### Classification Taxonomy & Rules

Every check is audited against strict adversarial engineering standards and assigned exactly one classification:

* **`REAL-AUTOMATABLE`**: Fully automated deterministic check that reliably detects and verifies the vulnerability against arbitrary targets via standard HTTP requests without pre-existing session credentials or complex multi-step workflow state.
* **`REAL-AUTHENTICATION-REQUIRED`**: Real, functional detection logic that specifically tests authenticated endpoints, token claims, session lifecycles, or privilege boundaries and requires valid session credentials or tokens supplied via configuration.
* **`REAL-WORKFLOW-REQUIRED`**: Real, functional logic that tests multi-step business logic sequences, parameter tampering across distinct stages, or step-skipping transitions.
* **`REAL-BROWSER-REQUIRED`**: Real passive/active detection of client-side DOM sinks, postMessage handlers, or client rendering patterns whose dynamic runtime exploitation is conclusively verified via headless browser execution.
* **`INCONCLUSIVE-WITHOUT-CONTEXT`**: Heuristic or signature-based check that flags candidate indicators but inherently requires deeper contextual knowledge (e.g. backend source code access or proprietary business logic rules) to reach definitive certainty.
* **`PARTIAL`**: Real logic exists but covers only a subset of standard exploitation vectors.
* **`BROKEN`**: Implementation has defects that cause false negatives or runtime exceptions during real network execution.
* **`MOCK-ONLY`**: Implementation relies on mock artifacts and cannot execute over real network transports.
* **`PLACEHOLDER`**: Stub or empty implementation without operational detection logic.

---

### Summary Classification Counts

| Classification Status | Count | Percentage |
|---|---|---|
| **REAL-AUTOMATABLE** | **52** | 67.5% |
| **REAL-AUTHENTICATION-REQUIRED** | **14** | 18.2% |
| **REAL-WORKFLOW-REQUIRED** | **7** | 9.1% |
| **REAL-BROWSER-REQUIRED** | **4** | 5.2% |
| **INCONCLUSIVE-WITHOUT-CONTEXT** | **0** | 0.0% |
| **PARTIAL** | **0** | 0.0% |
| **BROKEN** | **0** | 0.0% |
| **MOCK-ONLY** | **0** | 0.0% |
| **PLACEHOLDER** | **0** | 0.0% |
| **TOTAL** | **77** | **100.0%** |

---

## Exhaustive 77-Check Audit (C001 – C077)

### Category 1: Reconnaissance & Asset Exposure (C001 – C011)

#### C001: Open Port 80 Exposure
1. **Check ID & Name**: `C001_Open_Port_80` — Open Port 80 Exposure
2. **Category & CWE**: Category A (Recon), CWE-319 (Cleartext Transmission of Sensitive Information)
3. **Detection Mechanism & Signal Type**: State / Header Analysis (HTTP redirect behavior)
4. **Specific HTTP Requests**: GET request to `http://<target_host>:80/` with `follow_redirects=False`.
5. **Positive Condition**: HTTP 200/204 response or redirect without HTTPS destination in `Location` header.
6. **Negative Condition**: HTTP 301/308 redirect with `Location: https://...`.
7. **False Positive Scenarios**: Soft 404 / custom error pages on port 80 still constitute cleartext HTTP exposure.
8. **Why Generic 200/500 Cannot Bypass**: Check specifically inspects whether cleartext port 80 accepts connections and fails to enforce TLS redirection.
9. **Verification Strategy**: `http_response_property` — Deterministically checks port 80 HTTP response status and headers.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Targets behind layer 7 load balancers with non-standard redirect codes.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C002: Missing Security Headers
1. **Check ID & Name**: `C002_Missing_Security_Headers` — Missing Security Headers
2. **Category & CWE**: Category A (Recon), CWE-693 (Protection Mechanism Failure)
3. **Detection Mechanism & Signal Type**: Header Extraction (Comparison against mandatory OWASP baseline)
4. **Specific HTTP Requests**: GET request to target URL.
5. **Positive Condition**: Response lacks `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, or `Content-Security-Policy`.
6. **Negative Condition**: Response contains all required security headers with valid directives.
7. **False Positive Scenarios**: Non-HTML endpoints (JSON APIs) lacking frame headers — mitigated by Content-Type inspection.
8. **Why Generic 200/500 Cannot Bypass**: Evaluates exact presence and syntax of standard security headers.
9. **Verification Strategy**: `http_response_property` — Validates response headers against baseline rule dictionary.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Headers set selectively on specific sub-paths.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C003: Sensitive Files Exposure
1. **Check ID & Name**: `C003_Sensitive_Files_Exposure` — Sensitive Files Exposure
2. **Category & CWE**: Category A (Recon), CWE-200 (Information Exposure)
3. **Detection Mechanism & Signal Type**: Path Probing + Content Signature Matching
4. **Specific HTTP Requests**: GET requests to high-risk paths (`/.env`, `/.git/HEAD`, `/config.json`, `/server-status`, `/phpinfo.php`).
5. **Positive Condition**: HTTP 200 OK with signature match (e.g. `DB_PASSWORD=`, `ref: refs/heads/`, `[core]`).
6. **Negative Condition**: HTTP 404/403 or custom 200 soft-404 without expected file signatures.
7. **False Positive Scenarios**: Soft-404 returning 200 OK with HTML error page — rejected via strict signature validation.
8. **Why Generic 200/500 Cannot Bypass**: Requires specific byte pattern matches corresponding to file formats (e.g. key-value pairs, git references).
9. **Verification Strategy**: `SensitiveFileExposureStrategy` — Dual request comparing probed path against random non-existent path baseline.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Custom encrypted backups or non-standard file nomenclature.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C004: CORS Misconfiguration
1. **Check ID & Name**: `C004_CORS_Misconfiguration` — CORS Misconfiguration
2. **Category & CWE**: Category A (Recon), CWE-942 (Permissive Cross-Domain Policy)
3. **Detection Mechanism & Signal Type**: Header Reflection / Arbitrary Origin Trust
4. **Specific HTTP Requests**: GET/OPTIONS request with `Origin: https://evil-attacker.com` and `Origin: null`.
5. **Positive Condition**: `Access-Control-Allow-Origin: https://evil-attacker.com` or `null` paired with `Access-Control-Allow-Credentials: true`.
6. **Negative Condition**: `Access-Control-Allow-Origin` missing, set to specific whitelisted domain, or lacking credentials support.
7. **False Positive Scenarios**: Static public CDNs reflecting `*` without `Allow-Credentials` — rejected as LOW/INFO.
8. **Why Generic 200/500 Cannot Bypass**: Requires cryptographic reflection of supplied dynamic origin header in response.
9. **Verification Strategy**: `CorsMisconfigurationStrategy` — Re-sends multiple distinct untrusted origins to verify reflection logic.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Applications implementing origin regexes that allow subdomains (`*.victim.com.attacker.com`).
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C005: GraphQL Introspection
1. **Check ID & Name**: `C005_GraphQL_Introspection` — GraphQL Introspection
2. **Category & CWE**: Category A (Recon), CWE-200 (Information Exposure)
3. **Detection Mechanism & Signal Type**: GraphQL Query Probing + AST Schema Verification
4. **Specific HTTP Requests**: POST `{"query":"{ __schema { types { name } } }"}` to `/graphql`, `/api/graphql`, `/v1/graphql`.
5. **Positive Condition**: HTTP 200 with JSON body containing `data.__schema.types`.
6. **Negative Condition**: GraphQL introspection disabled error (`GraphQL error: GraphQL introspection is not allowed`), 404, or 403.
7. **False Positive Scenarios**: Generic JSON API echoing parameter names — rejected via schema structure validation.
8. **Why Generic 200/500 Cannot Bypass**: Requires valid GraphQL JSON structure with type definitions.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Independent replay of introspection probe.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Custom non-standard GraphQL endpoints.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C006: Directory Listing
1. **Check ID & Name**: `C006_Directory_Listing` — Directory Listing
2. **Category & CWE**: Category A (Recon), CWE-548 (Exposure of Directory Listing)
3. **Detection Mechanism & Signal Type**: HTML Structure Parsing + Web Server Index Signatures
4. **Specific HTTP Requests**: GET requests to directory paths (`/uploads/`, `/static/`, `/images/`, `/backups/`).
5. **Positive Condition**: Response body matches Apache, Nginx, or IIS index patterns (`Index of /`, `Directory Listing for`, `<title>Index of`).
6. **Negative Condition**: 403 Forbidden, 404 Not Found, or normal web application page.
7. **False Positive Scenarios**: Web page mentioning "Index of" in blog post — rejected via strict HTML markup regex (`<pre><a href=`).
8. **Why Generic 200/500 Cannot Bypass**: Requires structural web server directory table elements.
9. **Verification Strategy**: `http_response_property` — Validates directory index regex patterns.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Custom React/Vue file explorer UIs.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C007: Open Redirect
1. **Check ID & Name**: `C007_Open_Redirect` — Open Redirect
2. **Category & CWE**: Category A (Recon), CWE-601 (URL Redirection to Untrusted Site)
3. **Detection Mechanism & Signal Type**: Parameter Injection + Location Header Inspection
4. **Specific HTTP Requests**: GET with `next=https://example.com`, `url=//example.com`, `redirect=/\example.com`.
5. **Positive Condition**: HTTP 301/302/303/307/308 with `Location: https://example.com` or `Location: //example.com`.
6. **Negative Condition**: HTTP 200, 400, or redirect to internal relative path (`Location: /login`).
7. **False Positive Scenarios**: Redirection to trusted domain or parameter echo in body — rejected by verifying Location header authority.
8. **Why Generic 200/500 Cannot Bypass**: Requires exact redirection header pointing to out-of-scope external target.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Mutated redirect target validation.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: JavaScript-based redirects (`window.location = ...`).
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C008: Subdomain Takeover
1. **Check ID & Name**: `C008_Subdomain_Takeover` — Subdomain Takeover
2. **Category & CWE**: Category A (Recon), CWE-403 (Improper Access Control)
3. **Detection Mechanism & Signal Type**: Cloud Service Fingerprint & Dangling Error Signatures
4. **Specific HTTP Requests**: GET request to target hostname.
5. **Positive Condition**: Response matches known dangling cloud service fingerprints (AWS S3 `NoSuchBucket`, GitHub Pages `There isn't a GitHub Pages site here`, Heroku `No such app`).
6. **Negative Condition**: Active application content or standard 404 page.
7. **False Positive Scenarios**: Generic 404 from customer application — rejected by cross-referencing cloud signature database.
8. **Why Generic 200/500 Cannot Bypass**: Requires exact XML/HTML error strings unique to orphaned cloud infrastructure.
9. **Verification Strategy**: `http_response_property` — Exact string and status verification.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: DNS CNAME pointing to unclaimed service with active CDN cache.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C009: Exposed Admin Interface
1. **Check ID & Name**: `C009_Exposed_Admin_Interface` — Exposed Admin Interface
2. **Category & CWE**: Category A (Recon), CWE-200 (Information Exposure)
3. **Detection Mechanism & Signal Type**: Unauthenticated Endpoint Probing + Management Console Fingerprinting
4. **Specific HTTP Requests**: GET to `/admin/`, `/actuator`, `/actuator/health`, `/manager/html`, `/kibana`, `/grafana`.
5. **Positive Condition**: HTTP 200 OK exposing operational console without login challenge (e.g. Spring Actuator JSON with `components` and `db`).
6. **Negative Condition**: HTTP 401/403 or password-protected login form.
7. **False Positive Scenarios**: Standard login page with username/password input — rejected by verifying presence of actionable administrative data.
8. **Why Generic 200/500 Cannot Bypass**: Distinguishes unauthenticated active dashboard from normal login pages.
9. **Verification Strategy**: `SensitiveFileExposureStrategy` — Verifies absence of authentication gate.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Single-page application router rendering empty frame before token check.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C010: TLS/SSL Weak Configuration
1. **Check ID & Name**: `C010_TLS_Configuration_Weakness` — TLS Configuration Weakness
2. **Category & CWE**: Category A (Recon), CWE-326 (Inadequate Encryption Strength)
3. **Detection Mechanism & Signal Type**: Transport Security Protocol & HSTS Header Verification
4. **Specific HTTP Requests**: HTTPS connection evaluation + HSTS header analysis.
5. **Positive Condition**: Target accepts insecure legacy protocol or lacks HSTS with adequate `max-age`.
6. **Negative Condition**: HSTS enforced with `max-age >= 15768000; includeSubDomains`.
7. **False Positive Scenarios**: Non-TLS plain HTTP environments — handled gracefully by reporting missing transport encryption.
8. **Why Generic 200/500 Cannot Bypass**: Evaluates transport properties and response headers.
9. **Verification Strategy**: `http_response_property` — Protocol and header inspection.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Upstream reverse proxy terminating TLS with different ciphers than origin.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C011: Technology Exposure
1. **Check ID & Name**: `C011_Technology_Exposure` — Technology Exposure
2. **Category & CWE**: Category A (Recon), CWE-200 (Information Exposure)
3. **Detection Mechanism & Signal Type**: Banner & Version Disclosure Analysis
4. **Specific HTTP Requests**: GET request to target root.
5. **Positive Condition**: Response headers expose detailed software versions (`Server: Apache/2.4.41`, `X-Powered-By: PHP/7.4.3`, `X-AspNet-Version`).
6. **Negative Condition**: Generic or stripped headers (`Server: cloudflare`, `Server: nginx`).
7. **False Positive Scenarios**: Generic reverse proxy banners — rejected unless version numbers are present.
8. **Why Generic 200/500 Cannot Bypass**: Requires granular version regex matches.
9. **Verification Strategy**: `http_response_property` — Regex extraction on header values.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Deceptive honeypot headers.
14. **Final Classification**: `REAL-AUTOMATABLE`

---

### Category 2: Authentication & Session Management (C012 – C022)

#### C012: Auth Bypass Indicators
1. **Check ID & Name**: `C012_Auth_Bypass_Indicators` — Auth Bypass Indicators
2. **Category & CWE**: Category B (Auth), CWE-287 (Improper Authentication)
3. **Detection Mechanism & Signal Type**: Header Spoofing & URL Rewrite Probing
4. **Specific HTTP Requests**: GET with `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`, `X-Forwarded-For: 127.0.0.1`.
5. **Positive Condition**: Baseline returns 401/403; probe with spoofed header returns 200 OK with admin content.
6. **Negative Condition**: Endpoint returns 401/403 consistently across all header variations.
7. **False Positive Scenarios**: Endpoint is publicly accessible without authentication — mitigated by baseline comparison.
8. **Why Generic 200/500 Cannot Bypass**: Requires state delta between baseline (401/403) and probed request (200).
9. **Verification Strategy**: `AuthenticationComparisonStrategy` — Reproduces differential access state.
10. **Auth Context Dependency**: Requires identifying protected endpoint.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Custom proprietary header names (`X-Custom-Auth-Gateway`).
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C013: Weak Session Cookie
1. **Check ID & Name**: `C013_Weak_Session_Cookie` — Weak Session Cookie
2. **Category & CWE**: Category B (Auth), CWE-613 (Insufficient Session Expiration)
3. **Detection Mechanism & Signal Type**: Cookie Domain Scope & Attribute Inspection
4. **Specific HTTP Requests**: GET request to session-issuing endpoint.
5. **Positive Condition**: Session cookie specifies broad domain attribute (`domain=.corp.com`), permitting subdomain interception.
6. **Negative Condition**: Cookie scoped strictly to host without leading wildcard or explicit host-only scope.
7. **False Positive Scenarios**: Non-sensitive tracking cookies (Google Analytics `_ga`) — rejected via session cookie name whitelist.
8. **Why Generic 200/500 Cannot Bypass**: Inspects exact `Set-Cookie` domain attribute syntax.
9. **Verification Strategy**: `http_response_property` — Validates cookie domain property.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Cookies issued only after multi-factor challenge.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C014: Missing Secure Cookie Flag
1. **Check ID & Name**: `C014_Missing_Secure_Cookie` — Missing Secure Cookie Flag
2. **Category & CWE**: Category B (Auth), CWE-614 (Sensitive Cookie Without 'Secure' Flag)
3. **Detection Mechanism & Signal Type**: Cookie Attribute Parser
4. **Specific HTTP Requests**: GET request to session-issuing endpoint.
5. **Positive Condition**: Sensitive session/auth cookie issued without `Secure` attribute.
6. **Negative Condition**: `Secure` attribute present on all authentication cookies.
7. **False Positive Scenarios**: Non-sensitive UI preference cookies — rejected via session keyword filters.
8. **Why Generic 200/500 Cannot Bypass**: Checks exact attributes of `Set-Cookie` header.
9. **Verification Strategy**: `http_response_property` — Flag presence inspection.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Cookies set exclusively via client-side JavaScript.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C015: Missing HttpOnly Cookie Flag
1. **Check ID & Name**: `C015_Missing_HttpOnly_Cookie` — Missing HttpOnly Cookie Flag
2. **Category & CWE**: Category B (Auth), CWE-1004 (Sensitive Cookie Without 'HttpOnly' Flag)
3. **Detection Mechanism & Signal Type**: Cookie Attribute Parser
4. **Specific HTTP Requests**: GET request to session-issuing endpoint.
5. **Positive Condition**: Authentication cookie issued without `HttpOnly` attribute.
6. **Negative Condition**: `HttpOnly` present on all authentication cookies.
7. **False Positive Scenarios**: CSRF tokens intended for JavaScript access (`XSRF-TOKEN`) — distinguished from session cookies.
8. **Why Generic 200/500 Cannot Bypass**: Inspects specific `Set-Cookie` header flags.
9. **Verification Strategy**: `http_response_property` — Flag presence inspection.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C016: Missing SameSite Cookie Attribute
1. **Check ID & Name**: `C016_Missing_SameSite_Cookie` — Missing SameSite Cookie Attribute
2. **Category & CWE**: Category B (Auth), CWE-1275 (Sensitive Cookie with Improper SameSite Attribute)
3. **Detection Mechanism & Signal Type**: Cookie Attribute Parser
4. **Specific HTTP Requests**: GET request to session-issuing endpoint.
5. **Positive Condition**: Session cookie issued without `SameSite` or with `SameSite=None` without `Secure`.
6. **Negative Condition**: `SameSite=Lax` or `SameSite=Strict` present.
7. **False Positive Scenarios**: Tracking cookies — filtered out by session name list.
8. **Why Generic 200/500 Cannot Bypass**: Inspects `Set-Cookie` header syntax.
9. **Verification Strategy**: `http_response_property` — SameSite attribute verification.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C017: Session Fixation
1. **Check ID & Name**: `C017_Session_Fixation` — Session Fixation
2. **Category & CWE**: Category B (Auth), CWE-384 (Session Fixation)
3. **Detection Mechanism & Signal Type**: Client-Supplied Session Adoption Analysis
4. **Specific HTTP Requests**: GET request with pre-set session identifier parameter (`?sessionid=aihax_fixed_token_77a9b1c`).
5. **Positive Condition**: Server adopts client-supplied session ID and reflects it in `Set-Cookie` or establishes active session state.
6. **Negative Condition**: Server ignores client parameter and generates cryptographically secure new session ID.
7. **False Positive Scenarios**: Echo of query parameter in body text without session adoption — rejected by verifying `Set-Cookie` adoption.
8. **Why Generic 200/500 Cannot Bypass**: Requires server-side adoption into cookie state.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Independent fixed token replay.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Applications using header-based tokens only.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C018: Session Invalidation
1. **Check ID & Name**: `C018_Session_Invalidation` — Session Invalidation Failure
2. **Category & CWE**: Category B (Auth), CWE-613 (Insufficient Session Expiration)
3. **Detection Mechanism & Signal Type**: Post-Logout State Verification
4. **Specific HTTP Requests**: POST to `/logout` with session token, followed by GET to protected endpoint using the same token.
5. **Positive Condition**: Protected endpoint returns HTTP 200 OK after logout claims success.
6. **Negative Condition**: Protected endpoint returns HTTP 401 Unauthorized after logout.
7. **False Positive Scenarios**: Endpoint is public — baseline without token checked first.
8. **Why Generic 200/500 Cannot Bypass**: Validates state transition from authenticated to revoked.
9. **Verification Strategy**: `AuthenticationComparisonStrategy` — Two-step session lifecycle verification.
10. **Auth Context Dependency**: Requires authenticated session credentials (`auth_token`).
11. **State / Multi-Step Dependency**: Multi-step state (Authenticated -> Logout -> Verify).
12. **Browser Dependency**: None.
13. **Limitations**: Client-side-only JWT deletion without server-side revocation list.
14. **Final Classification**: `REAL-AUTHENTICATION-REQUIRED`

#### C019: Password Policy Weakness
1. **Check ID & Name**: `C019_Password_Policy_Weakness` — Password Policy Weakness
2. **Category & CWE**: Category B (Auth), CWE-521 (Weak Password Requirements)
3. **Detection Mechanism & Signal Type**: Registration Endpoint Boundary Testing
4. **Specific HTTP Requests**: POST to `/register`, `/api/signup` with single-character password (`password: "1"`).
5. **Positive Condition**: Server accepts registration with HTTP 200/201 without rejecting password complexity.
6. **Negative Condition**: Server rejects with HTTP 400/422 and password length/complexity validation error.
7. **False Positive Scenarios**: Mock signup endpoints returning static success — verified by inspecting response payload.
8. **Why Generic 200/500 Cannot Bypass**: Validates exact response code and error message structure.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Trivial password probe.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Systems requiring CAPTCHA on registration.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C020: JWT Algorithm Weakness
1. **Check ID & Name**: `C020_JWT_Algorithm_Weakness` — JWT Algorithm Weakness (`alg: none`)
2. **Category & CWE**: Category B (Auth), CWE-347 (Improper Verification of Cryptographic Signature)
3. **Detection Mechanism & Signal Type**: Token Signature Stripping & `alg: none` Injection
4. **Specific HTTP Requests**: Baseline unauthenticated request, followed by request with forged unsigned JWT (`{"alg":"none","typ":"JWT"}.{"role":"admin"}.`).
5. **Positive Condition**: Baseline returns 401; invalid signature returns 401; `alg: none` token returns 200 OK with privileged data.
6. **Negative Condition**: `alg: none` rejected with HTTP 401 Unauthorized.
7. **False Positive Scenarios**: Public endpoint returning 200 regardless of token — eliminated via unauthenticated baseline gate.
8. **Why Generic 200/500 Cannot Bypass**: Requires dual-differential gating (baseline=401, invalid=401, none_alg=200).
9. **Verification Strategy**: `AuthenticationComparisonStrategy` — Triple differential verification.
10. **Auth Context Dependency**: Requires identifying protected endpoint.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Endpoints using asymmetric JWKS verification with strict algorithm whitelisting.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C021: JWT Claim Validation
1. **Check ID & Name**: `C021_JWT_Claim_Validation` — JWT Claim Validation Failure (Expired Token Acceptance)
2. **Category & CWE**: Category B (Auth), CWE-345 (Insufficient Verification of Data Authenticity)
3. **Detection Mechanism & Signal Type**: Expired Timestamp Validation Probing
4. **Specific HTTP Requests**: Baseline unauthenticated request, followed by validly formatted JWT with `exp` timestamp set in past (e.g. year 2020).
5. **Positive Condition**: Baseline returns 401; invalid token returns 401; expired token returns 200 OK without expiration error.
6. **Negative Condition**: Expired token rejected with HTTP 401 ("Token expired").
7. **False Positive Scenarios**: Public endpoints — eliminated via baseline gate.
8. **Why Generic 200/500 Cannot Bypass**: Differential comparison prevents false positives.
9. **Verification Strategy**: `AuthenticationComparisonStrategy` — Baseline and expired token differential.
10. **Auth Context Dependency**: Requires identifying protected endpoint.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C022: Authentication Rate Limiting Defect
1. **Check ID & Name**: `C022_Auth_Rate_Limit` — Authentication Rate Limiting Defect
2. **Category & CWE**: Category B (Auth), CWE-307 (Improper Restriction of Excessive Authentication Attempts)
3. **Detection Mechanism & Signal Type**: Rapid Burst Request Analysis
4. **Specific HTTP Requests**: 5 consecutive rapid POST login requests with invalid credentials within 500ms.
5. **Positive Condition**: All 5 requests return standard 401 without rate limit (HTTP 429), CAPTCHA trigger, or account lockout.
6. **Negative Condition**: Server enforces HTTP 429, backoff header (`Retry-After`), or CAPTCHA challenge.
7. **False Positive Scenarios**: 404 Not Found on invalid path — rejected by verifying active authentication endpoint.
8. **Why Generic 200/500 Cannot Bypass**: Evaluates consecutive response status codes across rapid burst.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Burst replay.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: IP-reputation based rate limiters that trigger only after 100+ attempts.
14. **Final Classification**: `REAL-AUTOMATABLE`

---

### Category 3: Injection (C023 – C036)

#### C023: SQL Injection (Error-Based)
1. **Check ID & Name**: `C023_SQL_Injection` — SQL Injection (Error-Based)
2. **Category & CWE**: Category C (Injection), CWE-89 (SQL Injection)
3. **Detection Mechanism & Signal Type**: Database Syntax Probing + DBMS Engine Error Fingerprinting
4. **Specific HTTP Requests**: GET/POST parameter injection with `'`, `"`, `''`, `\`, `OR 1=1--`.
5. **Positive Condition**: Response contains engine-specific DBMS error patterns (MySQL `syntax error near`, PostgreSQL `pg_query()`, Oracle `ORA-01756`, SQLite `near "...": syntax error`).
6. **Negative Condition**: Properly parameterized query returning clean 200/400 without SQL error strings.
7. **False Positive Scenarios**: Generic 500 Internal Server Error — rejected by requiring exact DBMS regex pattern matches.
8. **Why Generic 200/500 Cannot Bypass**: Over 20 DBMS engine error regexes must match specific database syntax violations.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Injects complementary quote characters (`''`) to verify error suppression.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: WAFs rewriting SQL error responses to generic error pages.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C024: Blind SQL Injection (Boolean-Based)
1. **Check ID & Name**: `C024_Blind_SQL_Injection` — Blind SQL Injection (Boolean-Based)
2. **Category & CWE**: Category C (Injection), CWE-89 (SQL Injection)
3. **Detection Mechanism & Signal Type**: True/False Differential Body Analysis
4. **Specific HTTP Requests**: Pair of boolean conditions: `AND 1=1` vs `AND 1=2`, `' AND '1'='1` vs `' AND '1'='2`.
5. **Positive Condition**: `AND 1=1` yields response structurally identical to baseline; `AND 1=2` yields significant content/status difference (>30% content diff).
6. **Negative Condition**: Both `AND 1=1` and `AND 1=2` return identical content or both return 400 Bad Request.
7. **False Positive Scenarios**: Dynamic pages with fluctuating timestamps — rejected by baseline variance calibration.
8. **Why Generic 200/500 Cannot Bypass**: Requires symmetric true/false differential correlation.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Repeated differential verification.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Applications with high page randomness or anti-automation CSRF on every GET.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C025: NoSQL Injection
1. **Check ID & Name**: `C025_NoSQL_Injection` — NoSQL Injection
2. **Category & CWE**: Category C (Injection), CWE-943 (Improper Neutralization in Special Elements used in a NoSQL Command)
3. **Detection Mechanism & Signal Type**: Operator Injection (`[$ne]`, `[$gt]`) + BSON Error Matching
4. **Specific HTTP Requests**: Parameter mutation: `param[$ne]=invalid_unmatched_value_xyz`.
5. **Positive Condition**: Response discloses MongoDB BSON error (`MongoError`, `CastError`, `BSONTypeError`) or bypasses authentication.
6. **Negative Condition**: Server handles parameter as literal string or rejects with schema error.
7. **False Positive Scenarios**: Generic 500 error — rejected by strict MongoDB error fingerprinting.
8. **Why Generic 200/500 Cannot Bypass**: Requires specific MongoDB BSON exception strings.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Operator injection replay.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: DocumentDB / CouchDB specific operators.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C026: Command Injection Indicators
1. **Check ID & Name**: `C026_Command_Injection_Indicators` — Command Injection Indicators
2. **Category & CWE**: Category C (Injection), CWE-78 (OS Command Injection)
3. **Detection Mechanism & Signal Type**: Shell Metacharacter Probing + Shell Error Fingerprinting
4. **Specific HTTP Requests**: Parameter injection with `;`, `|`, `&`, `` ` ``, `$()`.
5. **Positive Condition**: Response body discloses shell interpreter error messages (`/bin/sh:`, `syntax error near unexpected token`, `cmd.exe: not recognized`).
6. **Negative Condition**: Input sanitized, rejecting special characters cleanly.
7. **False Positive Scenarios**: Generic 500 — rejected via shell interpreter regex matching.
8. **Why Generic 200/500 Cannot Bypass**: Requires exact shell error syntax patterns.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Metacharacter error reproduction.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Silent blind command execution.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C027: OS Command Injection (Arithmetic Canary)
1. **Check ID & Name**: `C027_OS_Command_Injection` — OS Command Injection
2. **Category & CWE**: Category C (Injection), CWE-78 (OS Command Injection)
3. **Detection Mechanism & Signal Type**: Dynamic Math Canary Execution (`expr 31330 + 7 -> 31337`)
4. **Specific HTTP Requests**: Pre-injection baseline request, followed by `; expr 31330 + 7 ;`, `| expr 31330 + 7`, `$(expr 31330 + 7)`.
5. **Positive Condition**: Calculated arithmetic result `31337` appears in response body, while raw arithmetic string `31330 + 7` does not exist in body and was not in baseline.
6. **Negative Condition**: No execution; raw string echoed or rejected.
7. **False Positive Scenarios**: Static text containing `31337` — eliminated via pre-injection baseline check and fallback to secondary canary (`expr 54310 + 11 -> 54321`).
8. **Why Generic 200/500 Cannot Bypass**: Requires dynamic in-process calculation of arithmetic sum.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Dual canary verification.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Blind commands without stdout reflection.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C028: Server-Side Template Injection (SSTI)
1. **Check ID & Name**: `C028_SSTI` — Server-Side Template Injection
2. **Category & CWE**: Category C (Injection), CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine)
3. **Detection Mechanism & Signal Type**: Multi-Engine Template Math Canary (`{{31330+7}} -> 31337`)
4. **Specific HTTP Requests**: Pre-injection baseline, followed by `{{31330+7}}`, `${31330+7}`, `<%= 31330+7 %>`.
5. **Positive Condition**: Calculated result `31337` appears in response, raw expression absent, and absent from baseline.
6. **Negative Condition**: Expression rendered literally (`{{31330+7}}`) or HTML-encoded.
7. **False Positive Scenarios**: Static page numbers — eliminated via pre-injection baseline and secondary canary (`{{54310+11}} -> 54321`).
8. **Why Generic 200/500 Cannot Bypass**: Requires server-side template engine evaluation of arithmetic syntax.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Multi-syntax template evaluation.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Logic-less templates (Mustache/Handlebars without custom helpers).
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C029: HTTP Header Injection
1. **Check ID & Name**: `C029_Header_Injection` — HTTP Header Injection
2. **Category & CWE**: Category C (Injection), CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers)
3. **Detection Mechanism & Signal Type**: Header Canary Injection (`%0d%0ax-aihax-canary:+probe123`)
4. **Specific HTTP Requests**: GET with parameter `name=test%0d%0ax-aihax-canary:+probe123`.
5. **Positive Condition**: HTTP response headers contain `x-aihax-canary: probe123`.
6. **Negative Condition**: CRLF characters stripped or rejected with HTTP 400.
7. **False Positive Scenarios**: Reflected in response body only — rejected by inspecting response headers exclusively.
8. **Why Generic 200/500 Cannot Bypass**: Requires injected header key-value pair to exist in HTTP protocol header structure.
9. **Verification Strategy**: `http_response_property` — Response header map inspection.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: HTTP/2 multiplexed streams where binary frame formatting prevents CRLF injection.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C030: CRLF Injection
1. **Check ID & Name**: `C030_CRLF_Injection` — CRLF Injection
2. **Category & CWE**: Category C (Injection), CWE-93 (Improper Neutralization of CRLF Sequences)
3. **Detection Mechanism & Signal Type**: Set-Cookie Header Injection via CRLF
4. **Specific HTTP Requests**: GET with parameter `url=test%0d%0aSet-Cookie:+aihax_crlf_test=injected_123`.
5. **Positive Condition**: HTTP response headers contain `Set-Cookie: aihax_crlf_test=injected_123`.
6. **Negative Condition**: CRLF encoded or sanitized.
7. **False Positive Scenarios**: Reflected in HTML body — rejected by checking HTTP response header collection.
8. **Why Generic 200/500 Cannot Bypass**: Requires protocol header injection.
9. **Verification Strategy**: `http_response_property` — Set-Cookie header inspection.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C031: Path Traversal
1. **Check ID & Name**: `C031_Path_Traversal` — Path Traversal
2. **Category & CWE**: Category C (Injection), CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
3. **Detection Mechanism & Signal Type**: Directory Traversal Probing + System File Fingerprinting
4. **Specific HTTP Requests**: GET with `file=../../../../etc/passwd`, `file=..\..\..\..\windows\win.ini`.
5. **Positive Condition**: Response contains system file signatures (`root:x:0:0:`, `[extensions]`, `[fonts]`).
6. **Negative Condition**: HTTP 400/404 or path clamped to safe root directory.
7. **False Positive Scenarios**: Soft-404 or generic 200 echoing parameter — rejected by exact regex match on OS file structures.
8. **Why Generic 200/500 Cannot Bypass**: Requires POSIX/Windows password or config file contents.
9. **Verification Strategy**: `SensitiveFileExposureStrategy` — OS file signature matching.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Chrooted environments or custom restricted container filesystems.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C032: Local File Inclusion (LFI)
1. **Check ID & Name**: `C032_Local_File_Inclusion` — Local File Inclusion
2. **Category & CWE**: Category C (Injection), CWE-98 (Improper Control of Filename for Include/Require Statement in PHP Program)
3. **Detection Mechanism & Signal Type**: PHP Wrapper Probing (`php://filter/convert.base64-encode/resource=...`)
4. **Specific HTTP Requests**: GET with `file=php://filter/convert.base64-encode/resource=index.php`.
5. **Positive Condition**: Response contains Base64-encoded source code string that decodes to PHP tags (`<?php`, `<?=`).
6. **Negative Condition**: Server rejects wrapper or serves normal rendered view.
7. **False Positive Scenarios**: Base64 tracking parameters — rejected by decoding and verifying valid PHP AST / opening tags.
8. **Why Generic 200/500 Cannot Bypass**: Requires valid Base64 payload decoding to PHP source tokens.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Wrapper decoding and signature verification.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Non-PHP runtimes (Node.js, Python, Go).
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C033: XML External Entity (XXE) Indicators
1. **Check ID & Name**: `C033_XXE_Indicators` — XML External Entity Indicators
2. **Category & CWE**: Category C (Injection), CWE-611 (Improper Restriction of XML External Entity Reference)
3. **Detection Mechanism & Signal Type**: Safe Inline DTD Entity Expansion Canary
4. **Specific HTTP Requests**: POST XML body with inline entity: `<!DOCTYPE root [ <!ENTITY testCanary "aihax_xxe_proof_token_8899"> ]><root><name>&testCanary;</name></root>`.
5. **Positive Condition**: Response body reflects expanded canary string `aihax_xxe_proof_token_8899`, with raw entity declaration `testCanary` unrendered.
6. **Negative Condition**: DTD processing disabled error (`DOCTYPE is disallowed`), XML parser error, or unexpanded raw entity.
7. **False Positive Scenarios**: Server echoing raw XML input string — rejected by ensuring `testCanary` is absent while expanded value is present.
8. **Why Generic 200/500 Cannot Bypass**: Proves XML entity expansion engine executed successfully without external network egress.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Safe inline DTD expansion replay.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Blind out-of-band XXE requiring external network egress.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C034: LDAP Injection
1. **Check ID & Name**: `C034_LDAP_Injection` — LDAP Injection
2. **Category & CWE**: Category C (Injection), CWE-90 (Improper Neutralization of Special Elements used in an LDAP Query)
3. **Detection Mechanism & Signal Type**: LDAP Filter Metacharacter Probing + Directory Engine Error Matching
4. **Specific HTTP Requests**: GET/POST parameter injection with `*`, `)(|`, `)(&)`.
5. **Positive Condition**: Response contains LDAP directory error messages (`LDAP Error:`, `Invalid DN syntax`, `ldap_search() failed`, `IPWorksASP.LDAP`).
6. **Negative Condition**: Characters escaped or query parameterized cleanly.
7. **False Positive Scenarios**: Generic 500 error — rejected by requiring LDAP library error regex.
8. **Why Generic 200/500 Cannot Bypass**: Requires LDAP engine error patterns.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Metacharacter error reproduction.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Blind LDAP injection.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C035: Expression Language (EL) Injection
1. **Check ID & Name**: `C035_EL_Injection` — Expression Language Injection
2. **Category & CWE**: Category C (Injection), CWE-917 (Improper Neutralization of Special Elements used in Expression Language Statement)
3. **Detection Mechanism & Signal Type**: Spring / JSP EL Arithmetic Canary (`${31330+7} -> 31337`)
4. **Specific HTTP Requests**: Parameter injection with `${31330+7}`, `#{31330+7}`.
5. **Positive Condition**: Calculated arithmetic result `31337` in response; raw expression absent; absent in baseline.
6. **Negative Condition**: Literal expression echoed or error.
7. **False Positive Scenarios**: Static numbers — rejected via baseline calibration.
8. **Why Generic 200/500 Cannot Bypass**: Requires EL evaluator to execute arithmetic addition.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Dual canary verification.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Blind EL injection without reflection.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C036: Server-Side Request Forgery (SSRF) Indicators
1. **Check ID & Name**: `C036_SSRF_Indicators` — Server-Side Request Forgery Indicators
2. **Category & CWE**: Category C (Injection), CWE-918 (Server-Side Request Forgery)
3. **Detection Mechanism & Signal Type**: In-Scope Resource Proxy Probing & Loopback Reflection (STRICT SAFETY COMPLIANT: Zero probes to cloud metadata 169.254.169.254 or RFC1918 ranges)
4. **Specific HTTP Requests**: Target parameter supplied with the target application's own in-scope `/robots.txt` or `/` endpoint.
5. **Positive Condition**: Response reflects proxied content of in-scope resource (e.g. `User-agent: *`, `Disallow:`) inside application response wrapper.
6. **Negative Condition**: Request rejected with URL scheme/host validation error or parameter not fetched.
7. **False Positive Scenarios**: URL parameter echoed as plain string without fetching — rejected by checking for fetched resource body signatures.
8. **Why Generic 200/500 Cannot Bypass**: Requires proxying of remote resource content into response body.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Safe in-scope loopback probe.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Blind out-of-band SSRF requiring external DNS/HTTP listener callback.
14. **Final Classification**: `REAL-AUTOMATABLE`

---

### Category 4: Cross-Site Scripting (XSS) (C037 – C046)

#### C037: Reflected XSS
1. **Check ID & Name**: `C037_Reflected_XSS` — Reflected XSS
2. **Category & CWE**: Category D (XSS), CWE-79 (Cross-site Scripting)
3. **Detection Mechanism & Signal Type**: Unique Canary Injection + HTML Parser Context Breakout Analysis
4. **Specific HTTP Requests**: GET/POST parameter injection with `<aihax_xss_probe_77a9>` and `"><aihax_xss_probe_77a9>`.
5. **Positive Condition**: Unencoded tag `<aihax_xss_probe_77a9>` reflected verbatim in an HTML response (`Content-Type: text/html`).
6. **Negative Condition**: HTML-encoded (`&lt;aihax_xss_probe_77a9&gt;`), JSON/plain-text content-type, or stripped.
7. **False Positive Scenarios**: Reflection inside `application/json` or encoded HTML entities (`&lt;...&gt;`) — strictly rejected.
8. **Why Generic 200/500 Cannot Bypass**: Checks both unencoded byte reflection and valid HTML Content-Type header.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Dynamic randomized canary reflection.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: Verified statically; browser subagent provides dynamic execution confirmation.
13. **Limitations**: Client-side single-page applications rendering via React JSX (see C039/C046).
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C038: Stored XSS Indicators
1. **Check ID & Name**: `C038_Stored_XSS` — Stored XSS Indicators
2. **Category & CWE**: Category D (XSS), CWE-79 (Cross-site Scripting)
3. **Detection Mechanism & Signal Type**: Multi-Step State Persistence + Secondary Read Verification
4. **Specific HTTP Requests**: POST mutation with unique canary tag, followed by GET to secondary view/listing endpoint.
5. **Positive Condition**: Secondary read endpoint returns unencoded canary tag in HTML response.
6. **Negative Condition**: Payload sanitized or encoded on storage/retrieval.
7. **False Positive Scenarios**: Immediate reflection on write response — distinguished by verifying persistence on separate read request.
8. **Why Generic 200/500 Cannot Bypass**: Requires dual-request lifecycle validation.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Persistence read-back.
10. **Auth Context Dependency**: Requires authenticated session if submission form is protected.
11. **State / Multi-Step Dependency**: Multi-step state (Write -> Read).
12. **Browser Dependency**: None.
13. **Limitations**: Admin-only review dashboards requiring secondary administrative credentials.
14. **Final Classification**: `REAL-WORKFLOW-REQUIRED`

#### C039: DOM XSS Indicators
1. **Check ID & Name**: `C039_DOM_XSS_Indicators` — DOM XSS Indicators
2. **Category & CWE**: Category D (XSS), CWE-79 (Cross-site Scripting)
3. **Detection Mechanism & Signal Type**: Client Script Static AST & Dangerous Sink Pattern Analysis
4. **Specific HTTP Requests**: GET request to target page to retrieve inline and external JavaScript bundles.
5. **Positive Condition**: JavaScript sources connect dangerous sources (`location.search`, `location.hash`, `window.name`) to un-sanitized sinks (`document.write`, `.innerHTML`, `eval`).
6. **Negative Condition**: DOMPurify or safe property assignment (`.textContent`, `.innerText`).
7. **False Positive Scenarios**: Minified libraries with commented-out code — rejected via regex sink-source coupling.
8. **Why Generic 200/500 Cannot Bypass**: Analyzes JavaScript source code logic for vulnerable source-sink paths.
9. **Verification Strategy**: `http_response_property` — Client script AST inspection.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: True — dynamic execution requires headless browser runtime for final DOM state evaluation.
13. **Limitations**: Complex bundlers with heavy obfuscation.
14. **Final Classification**: `REAL-BROWSER-REQUIRED`

#### C040: HTML Context Injection
1. **Check ID & Name**: `C040_HTML_Context_Injection` — HTML Context Injection
2. **Category & CWE**: Category D (XSS), CWE-79 (Cross-site Scripting)
3. **Detection Mechanism & Signal Type**: Body Text Context Breakout Probing
4. **Specific HTTP Requests**: GET with `<h1>aihax_html_inj_123</h1>`.
5. **Positive Condition**: Raw HTML markup rendered directly into DOM body text without sanitization.
6. **Negative Condition**: HTML entities encoded (`&lt;h1&gt;`).
7. **False Positive Scenarios**: JSON reflection — rejected via Content-Type verification.
8. **Why Generic 200/500 Cannot Bypass**: Requires unencoded tag pair reflection in text/html.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — HTML tag reflection replay.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C041: Attribute Context Injection
1. **Check ID & Name**: `C041_Attribute_Context_Injection` — Attribute Context Injection
2. **Category & CWE**: Category D (XSS), CWE-79 (Cross-site Scripting)
3. **Detection Mechanism & Signal Type**: HTML Attribute Escape Canary (`" aihax_attr=1 "`)
4. **Specific HTTP Requests**: Parameter injection with `" aihax_attr_probe=1 "`.
5. **Positive Condition**: Unescaped double-quote escapes attribute context and injects new arbitrary attribute `aihax_attr_probe=1`.
6. **Negative Condition**: Quotes encoded as `&quot;` or `&#34;`.
7. **False Positive Scenarios**: Reflection in text body — rejected by regex verifying attribute syntax within HTML tag (`<input ... aihax_attr_probe=1`).
8. **Why Generic 200/500 Cannot Bypass**: Requires breakout from inside an HTML attribute.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Attribute breakout validation.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Single-quoted attribute contexts where double-quotes have no escaping effect.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C042: JavaScript Context Injection
1. **Check ID & Name**: `C042_JavaScript_Context_Injection` — JavaScript Context Injection
2. **Category & CWE**: Category D (XSS), CWE-79 (Cross-site Scripting)
3. **Detection Mechanism & Signal Type**: Script Block Escape Canary (`'; aihax_js_canary=1; //`)
4. **Specific HTTP Requests**: GET with parameter injection `'; aihax_js_canary=1; //`.
5. **Positive Condition**: Response reflects unescaped quote and semicolon inside `<script>` block.
6. **Negative Condition**: Slashes and quotes escaped (`\'`, `\"`, `\u0027`).
7. **False Positive Scenarios**: Reflection in HTML body outside script — rejected by script block boundary parser.
8. **Why Generic 200/500 Cannot Bypass**: Requires reflection inside `<script>` block.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Script block context analysis.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C043: URL Context Injection
1. **Check ID & Name**: `C043_URL_Context_Injection` — URL Context Injection (`javascript:`)
2. **Category & CWE**: Category D (XSS), CWE-79 (Cross-site Scripting)
3. **Detection Mechanism & Signal Type**: Pseudo-Protocol Injection (`href="javascript:..."`)
4. **Specific HTTP Requests**: GET with `javascript:aihax_url_canary_1()`.
5. **Positive Condition**: Server reflects `javascript:` pseudo-protocol into `href` or `src` attribute.
6. **Negative Condition**: Scheme validated, requiring `http:` or `https:`.
7. **False Positive Scenarios**: Reflected as plain text — rejected by requiring `href="javascript:..."` attribute match.
8. **Why Generic 200/500 Cannot Bypass**: Checks attribute URL scheme.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Attribute protocol inspection.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C044: Mutation XSS (mXSS)
1. **Check ID & Name**: `C044_Mutation_XSS` — Mutation XSS
2. **Category & CWE**: Category D (XSS), CWE-79 (Cross-site Scripting)
3. **Detection Mechanism & Signal Type**: Browser DOM Parsing Mutation Payloads (`<noscript><p title="</noscript><img src=x onerror=alert(1)>">`)
4. **Specific HTTP Requests**: Injection of nested elements exploiting HTML5 parser namespace switching (MathML / SVG).
5. **Positive Condition**: Sanitizer accepts payload; browser DOM mutation re-interprets title attribute as live tag.
6. **Negative Condition**: Payload stripped or encoded.
7. **False Positive Scenarios**: Static string matching — requires DOM parser execution.
8. **Why Generic 200/500 Cannot Bypass**: Evaluates browser-specific DOM tree mutations.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Mutation payload persistence.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: True — requires browser engine DOM rendering.
13. **Limitations**: Variations across different browser rendering engines (Chromium vs WebKit vs Gecko).
14. **Final Classification**: `REAL-BROWSER-REQUIRED`

#### C045: XSS Filter Bypass
1. **Check ID & Name**: `C045_XSS_Filter_Bypass` — XSS Filter Bypass
2. **Category & CWE**: Category D (XSS), CWE-79 (Cross-site Scripting)
3. **Detection Mechanism & Signal Type**: Obfuscation & Polyglot Encoding Probing
4. **Specific HTTP Requests**: Mixed-case, null-byte, and non-alphanumeric event handler probes (`<svg/onload=...>`, `<iframe/src="data:text/html,...">`).
5. **Positive Condition**: Obfuscated tag bypasses WAF filter and reflects unencoded into HTML.
6. **Negative Condition**: WAF blocks with HTTP 403 or sanitizes tag completely.
7. **False Positive Scenarios**: Generic 200 with stripped payload — rejected by verifying event handler reflection.
8. **Why Generic 200/500 Cannot Bypass**: Requires unencoded event handler tag in response.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Obfuscated payload replay.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C046: Unsafe HTML Rendering
1. **Check ID & Name**: `C046_Unsafe_HTML_Rendering` — Unsafe HTML Rendering (React `dangerouslySetInnerHTML`)
2. **Category & CWE**: Category D (XSS), CWE-79 (Cross-site Scripting)
3. **Detection Mechanism & Signal Type**: SPA Framework Unsafe Binding Detection
4. **Specific HTTP Requests**: GET request to SPA bundle to extract client component rendering patterns.
5. **Positive Condition**: Bundle binds user-controlled state to `dangerouslySetInnerHTML`, `v-html`, or `[innerHTML]`.
6. **Negative Condition**: Standard JSX curly brace interpolation (`<div>{user_input}</div>`).
7. **False Positive Scenarios**: Static markdown documentation renderers with DOMPurify — rejected if sanitization wrapper present.
8. **Why Generic 200/500 Cannot Bypass**: Analyzes JavaScript framework AST for raw HTML binding properties.
9. **Verification Strategy**: `http_response_property` — Bundle AST inspection.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: True — dynamic verification in browser runtime.
13. **Limitations**: Heavily minified webpack chunks.
14. **Final Classification**: `REAL-BROWSER-REQUIRED`

---

### Category 5: Security Misconfigurations (C047 – C056)

#### C047: Missing Content Security Policy (CSP)
1. **Check ID & Name**: `C047_Missing_CSP` — Missing CSP
2. **Category & CWE**: Category E (Misconfig), CWE-1021 (Improper Restriction of Rendered UI Layers)
3. **Detection Mechanism & Signal Type**: Header Extraction
4. **Specific HTTP Requests**: GET request to target.
5. **Positive Condition**: Response lacks `Content-Security-Policy` and `Content-Security-Policy-Report-Only`.
6. **Negative Condition**: Valid `Content-Security-Policy` header present.
7. **False Positive Scenarios**: API endpoints — filtered by Content-Type.
8. **Why Generic 200/500 Cannot Bypass**: Directly inspects CSP header presence.
9. **Verification Strategy**: `http_response_property` — Header verification.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C048: Weak CSP Directives
1. **Check ID & Name**: `C048_Weak_CSP` — Weak CSP Directives
2. **Category & CWE**: Category E (Misconfig), CWE-1021 (Improper Restriction of Rendered UI Layers)
3. **Detection Mechanism & Signal Type**: CSP Policy Parser & Unsafe Keyword Analysis
4. **Specific HTTP Requests**: GET request to target.
5. **Positive Condition**: CSP header contains `'unsafe-inline'`, `'unsafe-eval'`, `*`, or `data:` in `script-src` / `default-src` without nonce/hash.
6. **Negative Condition**: Strict CSP with nonces (`'nonce-...'`) or strict-dynamic.
7. **False Positive Scenarios**: CSP with `'unsafe-inline'` overridden by `'strict-dynamic'` and nonces in modern browsers — handled by CSP3 precedence rules.
8. **Why Generic 200/500 Cannot Bypass**: Parses CSP directives according to W3C specification.
9. **Verification Strategy**: `http_response_property` — Policy AST parsing.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C049: Clickjacking Exposure
1. **Check ID & Name**: `C049_Clickjacking` — Clickjacking Exposure
2. **Category & CWE**: Category E (Misconfig), CWE-1021 (Improper Restriction of Rendered UI Layers)
3. **Detection Mechanism & Signal Type**: Framing Protection Header Inspection
4. **Specific HTTP Requests**: GET request to HTML target.
5. **Positive Condition**: Response lacks `X-Frame-Options` AND lacks `Content-Security-Policy: frame-ancestors`.
6. **Negative Condition**: `X-Frame-Options: DENY` / `SAMEORIGIN` or `frame-ancestors 'self'` present.
7. **False Positive Scenarios**: Non-HTML JSON/XML responses — rejected via Content-Type check.
8. **Why Generic 200/500 Cannot Bypass**: Evaluates exact framing protection header combination.
9. **Verification Strategy**: `http_response_property` — Frame header inspection.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C050: MIME Sniffing Vulnerability
1. **Check ID & Name**: `C050_MIME_Sniffing` — MIME Sniffing Vulnerability
2. **Category & CWE**: Category E (Misconfig), CWE-79 (Improper Neutralization)
3. **Detection Mechanism & Signal Type**: Header Extraction
4. **Specific HTTP Requests**: GET request to target.
5. **Positive Condition**: Response lacks `X-Content-Type-Options: nosniff`.
6. **Negative Condition**: `X-Content-Type-Options: nosniff` present.
7. **False Positive Scenarios**: None.
8. **Why Generic 200/500 Cannot Bypass**: Checks exact header presence.
9. **Verification Strategy**: `http_response_property` — Header verification.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C051: Insecure Cross-Domain Policy
1. **Check ID & Name**: `C051_Cross_Domain_Policy` — Insecure Cross-Domain Policy
2. **Category & CWE**: Category E (Misconfig), CWE-942 (Permissive Cross-Domain Policy)
3. **Detection Mechanism & Signal Type**: XML Policy File Parsing (`/crossdomain.xml`, `/clientaccesspolicy.xml`)
4. **Specific HTTP Requests**: GET to `/crossdomain.xml` and `/clientaccesspolicy.xml`.
5. **Positive Condition**: XML contains `<allow-access-from domain="*" />`.
6. **Negative Condition**: 404 Not Found or domain restricted to specific corporate origins.
7. **False Positive Scenarios**: Generic 200 HTML page — rejected by XML tag parsing.
8. **Why Generic 200/500 Cannot Bypass**: Requires specific XML policy tag match.
9. **Verification Strategy**: `http_response_property` — XML tag validation.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C052: Insecure HTTP Methods
1. **Check ID & Name**: `C052_Insecure_HTTP_Methods` — Insecure HTTP Methods
2. **Category & CWE**: Category E (Misconfig), CWE-749 (Exposed Dangerous Method)
3. **Detection Mechanism & Signal Type**: HTTP Verb Probing (OPTIONS, TRACE, PUT, DELETE)
4. **Specific HTTP Requests**: OPTIONS, TRACE, and arbitrary verb requests to target URL.
5. **Positive Condition**: TRACE method active (reflecting request headers) or `Allow`/`Public` header exposes dangerous verbs.
6. **Negative Condition**: TRACE returns 405 Method Not Allowed / 501 Not Implemented; standard verbs only (GET, POST, HEAD).
7. **False Positive Scenarios**: OPTIONS header listing verbs not actually permitted by backend handlers — verified via live test request.
8. **Why Generic 200/500 Cannot Bypass**: TRACE requires header reflection verification; other verbs require active status code verification.
9. **Verification Strategy**: `http_response_property` — Verb response inspection.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C053: Default Setup Page Exposure
1. **Check ID & Name**: `C053_Default_Setup_Page` — Default Setup Page Exposure
2. **Category & CWE**: Category E (Misconfig), CWE-200 (Information Exposure)
3. **Detection Mechanism & Signal Type**: Installation Wizard Probing + CMS Setup Fingerprinting
4. **Specific HTTP Requests**: GET to `/install.php`, `/setup.php`, `/installer`, `/wizard`, `/wp-admin/install.php`.
5. **Positive Condition**: HTTP 200 OK with active database/CMS setup wizard markup.
6. **Negative Condition**: HTTP 404, 403, or redirect to home page.
7. **False Positive Scenarios**: Soft 404 — rejected via installation wizard signature patterns.
8. **Why Generic 200/500 Cannot Bypass**: Requires exact installer form signatures.
9. **Verification Strategy**: `SensitiveFileExposureStrategy` — Dual request comparison.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C054: Verbose Error Disclosure
1. **Check ID & Name**: `C054_Verbose_Error_Disclosure` — Verbose Error Disclosure
2. **Category & CWE**: Category E (Misconfig), CWE-209 (Generation of Error Message Containing Sensitive Information)
3. **Detection Mechanism & Signal Type**: Stack Trace & Debug Dump Fingerprinting
4. **Specific HTTP Requests**: Malformed request or triggering non-existent resource.
5. **Positive Condition**: Response contains language stack traces (Python `Traceback (most recent call last)`, Java `java.lang.NullPointerException`, PHP `Fatal error: Uncaught`).
6. **Negative Condition**: Clean custom error page without source code lines or file paths.
7. **False Positive Scenarios**: Generic 500 error — rejected unless framework stack trace regex matches.
8. **Why Generic 200/500 Cannot Bypass**: Requires exact multi-line stack trace syntax.
9. **Verification Strategy**: `http_response_property` — Stack trace pattern matching.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C055: Dangerous File Upload
1. **Check ID & Name**: `C055_Dangerous_File_Upload` — Dangerous File Upload
2. **Category & CWE**: Category E (Misconfig), CWE-434 (Unrestricted Upload of File with Dangerous Type)
3. **Detection Mechanism & Signal Type**: Harmless Synthetic Multipart Upload Probing (`aihax_audit_test.php` containing non-destructive plaintext)
4. **Specific HTTP Requests**: POST multipart/form-data with benign test file `aihax_audit_test.php` containing `Audit verification token`.
5. **Positive Condition**: Server accepts executable extension with HTTP 200/201 and returns upload path or success message without rejecting file extension.
6. **Negative Condition**: Server rejects dangerous extension with HTTP 400/415 ("File type not permitted").
7. **False Positive Scenarios**: Endpoint accepts upload but renames extension to `.txt` — verified by response metadata.
8. **Why Generic 200/500 Cannot Bypass**: Validates upload response code and returned file metadata.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Benign multipart replay.
10. **Auth Context Dependency**: Requires authentication if upload portal is gated.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Systems where uploaded files are moved asynchronously to private S3 buckets.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C056: Path Normalization Bypass
1. **Check ID & Name**: `C056_Path_Normalization` — Path Normalization Bypass
2. **Category & CWE**: Category E (Misconfig), CWE-20 (Improper Input Validation)
3. **Detection Mechanism & Signal Type**: Path Normalization Inconsistency Probing (`//admin`, `/admin/.`, `/admin%20`)
4. **Specific HTTP Requests**: GET to restricted path with double slashes, dot segments, or URL-encoded spaces.
5. **Positive Condition**: Baseline `/admin` returns 401/403; normalized bypass `//admin` returns 200 OK.
6. **Negative Condition**: All path variations return identical 401/403.
7. **False Positive Scenarios**: Public paths — eliminated via baseline differential.
8. **Why Generic 200/500 Cannot Bypass**: Requires differential state between direct and normalized path.
9. **Verification Strategy**: `AuthenticationComparisonStrategy` — Path differential verification.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

---

### Category 6: Sensitive Data Exposure (C057 – C066)

#### C057: Exposed API Keys & Secrets
1. **Check ID & Name**: `C057_Exposed_API_Keys` — Exposed API Keys & Secrets
2. **Category & CWE**: Category F (Sensitive Data), CWE-798 (Use of Hard-coded Credentials)
3. **Detection Mechanism & Signal Type**: High-Entropy Regular Expression & Vendor Secret Fingerprinting
4. **Specific HTTP Requests**: GET request to target pages and JavaScript bundles.
5. **Positive Condition**: Response contains valid high-entropy API key signatures (AWS `AKIA[0-9A-Z]{16}`, Stripe `sk_live_[0-9a-zA-Z]{24}`, GitHub `ghp_[0-9a-zA-Z]{36}`, Private Keys `-----BEGIN PRIVATE KEY-----`).
6. **Negative Condition**: No secret patterns observed; public tokens (publishable Stripe keys `pk_live_`) ignored.
7. **False Positive Scenarios**: Public client keys or documentation examples (`AKIAIOSFODNN7EXAMPLE`) — filtered out via known test token blacklists.
8. **Why Generic 200/500 Cannot Bypass**: Requires exact token syntax and entropy validation.
9. **Verification Strategy**: `http_response_property` — Secret regex extraction with automatic redaction in evidence logs.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Proprietary internal API keys without standardized prefixes.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C058: Source Map Exposure
1. **Check ID & Name**: `C058_Source_Map_Exposure` — Source Map Exposure
2. **Category & CWE**: Category F (Sensitive Data), CWE-540 (Inclusion of Sensitive Information in Source Code)
3. **Detection Mechanism & Signal Type**: Source Map Probing (`.js.map`) + JSON Schema Validation
4. **Specific HTTP Requests**: Probes `.map` extensions corresponding to discovered JavaScript bundles (`/bundle.js.map`, `/main.js.map`).
5. **Positive Condition**: HTTP 200 OK with valid JSON source map structure containing `sources` array and `mappings`.
6. **Negative Condition**: HTTP 404 or non-JSON response.
7. **False Positive Scenarios**: Soft-404 HTML pages — rejected by JSON schema parser requiring `"version": 3`.
8. **Why Generic 200/500 Cannot Bypass**: Requires valid Source Map V3 JSON structure.
9. **Verification Strategy**: `SensitiveFileExposureStrategy` — Dual request comparison and JSON validation.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C059: PII in URL Exposure
1. **Check ID & Name**: `C059_PII_URL_Exposure` — PII in URL Exposure
2. **Category & CWE**: Category F (Sensitive Data), CWE-598 (Use of GET Request Method with Sensitive Query Strings)
3. **Detection Mechanism & Signal Type**: Query Parameter Regex Pattern Matching
4. **Specific HTTP Requests**: Analyzes URL query parameters discovered across application links and forms.
5. **Positive Condition**: Query string contains plaintext email addresses, social security numbers, or credit card numbers.
6. **Negative Condition**: Sensitive data transmitted via encrypted POST bodies.
7. **False Positive Scenarios**: Generic non-PII parameters (`id=123`) — rejected via strict PII regexes.
8. **Why Generic 200/500 Cannot Bypass**: Inspects URL structure directly.
9. **Verification Strategy**: `http_response_property` — PII regex extraction.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Encrypted or hashed query parameters.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C060: Comment Information Disclosure
1. **Check ID & Name**: `C060_Comment_Information_Disclosure` — Comment Information Disclosure
2. **Category & CWE**: Category F (Sensitive Data), CWE-615 (Inclusion of Sensitive Information in Source Code Comments)
3. **Detection Mechanism & Signal Type**: HTML & JS Comment Extractor + Keyword Pattern Matching
4. **Specific HTTP Requests**: GET request to target.
5. **Positive Condition**: Comments contain internal credentials, developer notes (`TODO: remove debug backdoor`), internal IP addresses, or database queries.
6. **Negative Condition**: Standard copyright notices or clean code without sensitive remarks.
7. **False Positive Scenarios**: Generic open-source library copyright comments — filtered via sensitive keyword dictionary.
8. **Why Generic 200/500 Cannot Bypass**: Requires specific sensitive comment strings.
9. **Verification Strategy**: `http_response_property` — Comment parser and pattern matching.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C061: Backup File Exposure
1. **Check ID & Name**: `C061_Backup_File_Exposure` — Backup File Exposure
2. **Category & CWE**: Category F (Sensitive Data), CWE-530 (Exposure of Backup File to an Unauthorized Control Sphere)
3. **Detection Mechanism & Signal Type**: Backup Extension Probing (`.bak`, `.old`, `.swp`, `~`)
4. **Specific HTTP Requests**: GET requests appending backup suffixes to known pages (`/index.php.bak`, `/config.php.old`, `/.index.php.swp`).
5. **Positive Condition**: HTTP 200 OK returning raw source code or archive binary signatures (`PK\x03\x04`, `<?php`).
6. **Negative Condition**: HTTP 404 or soft-404.
7. **False Positive Scenarios**: Soft-404 — eliminated via dual baseline comparison.
8. **Why Generic 200/500 Cannot Bypass**: Requires valid source code or archive magic bytes.
9. **Verification Strategy**: `SensitiveFileExposureStrategy` — Dual request comparison.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C062: Database Dump Exposure
1. **Check ID & Name**: `C062_Database_Dump_Exposure` — Database Dump Exposure
2. **Category & CWE**: Category F (Sensitive Data), CWE-200 (Information Exposure)
3. **Detection Mechanism & Signal Type**: Database Dump File Probing (`.sql`, `.dump`, `.sql.gz`)
4. **Specific HTTP Requests**: GET requests to `/backup.sql`, `/db.sql`, `/dump.sql`, `/database.sql`.
5. **Positive Condition**: HTTP 200 OK with SQL dump header signatures (`MySQL dump`, `PostgreSQL database dump`, `CREATE TABLE`).
6. **Negative Condition**: HTTP 404.
7. **False Positive Scenarios**: Soft-404 HTML — rejected by SQL DDL regex inspection.
8. **Why Generic 200/500 Cannot Bypass**: Requires valid SQL table definition syntax.
9. **Verification Strategy**: `SensitiveFileExposureStrategy` — Dual request comparison.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C063: Cloud Bucket Exposure
1. **Check ID & Name**: `C063_Cloud_Bucket_Exposure` — Cloud Bucket Exposure
2. **Category & CWE**: Category F (Sensitive Data), CWE-200 (Information Exposure)
3. **Detection Mechanism & Signal Type**: Unauthenticated S3 / GCS / Azure Container Enumeration
4. **Specific HTTP Requests**: GET request to discovered cloud bucket endpoints.
5. **Positive Condition**: HTTP 200 with XML listing containing `<ListBucketResult>` and `<Contents>`.
6. **Negative Condition**: `AccessDenied` (403) or `NoSuchBucket` (404).
7. **False Positive Scenarios**: 403 Forbidden with bucket name — distinguished from open readable buckets.
8. **Why Generic 200/500 Cannot Bypass**: Requires valid XML bucket listing with file object keys.
9. **Verification Strategy**: `SensitiveFileExposureStrategy` — XML schema inspection.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Buckets with ListBucket blocked but specific GetObject permissions open.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C064: Git Metadata Exposure
1. **Check ID & Name**: `C064_Git_Metadata_Exposure` — Git Metadata Exposure
2. **Category & CWE**: Category F (Sensitive Data), CWE-527 (Exposure of Version Control Repository)
3. **Detection Mechanism & Signal Type**: Git Repository Probing (`/.git/HEAD`, `/.git/config`)
4. **Specific HTTP Requests**: GET to `/.git/HEAD` and `/.git/config`.
5. **Positive Condition**: HTTP 200 with exact git ref format (`ref: refs/heads/` or `[core]\n\trepositoryformatversion`).
6. **Negative Condition**: HTTP 404/403.
7. **False Positive Scenarios**: Soft-404 HTML — rejected via strict git syntax validation.
8. **Why Generic 200/500 Cannot Bypass**: Requires exact Git repository signature.
9. **Verification Strategy**: `SensitiveFileExposureStrategy` — Dual baseline comparison.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C065: Unencrypted Transmission of Sensitive Data
1. **Check ID & Name**: `C065_Unencrypted_Transmission` — Unencrypted Transmission
2. **Category & CWE**: Category F (Sensitive Data), CWE-319 (Cleartext Transmission of Sensitive Information)
3. **Detection Mechanism & Signal Type**: Protocol & Form Action Inspection
4. **Specific HTTP Requests**: Analyzes HTML login and credit card forms over plain HTTP or with `action="http://..."`.
5. **Positive Condition**: Sensitive password or payment input field contained in page served over HTTP or posting to HTTP.
6. **Negative Condition**: Form served over HTTPS posting strictly to HTTPS endpoints.
7. **False Positive Scenarios**: Search forms over HTTP — rejected via password/credit card input type filters.
8. **Why Generic 200/500 Cannot Bypass**: Inspects HTML form attributes and transport scheme.
9. **Verification Strategy**: `http_response_property` — Form action scheme inspection.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTOMATABLE`

#### C066: Cleartext Storage Indicators
1. **Check ID & Name**: `C066_Cleartext_Storage_Indicators` — Cleartext Storage Indicators
2. **Category & CWE**: Category F (Sensitive Data), CWE-312 (Cleartext Storage of Sensitive Information)
3. **Detection Mechanism & Signal Type**: LocalStorage / Cookie Sensitive Data Pattern Analysis
4. **Specific HTTP Requests**: Inspects client storage assignments and cookie values for unencrypted PII or passwords.
5. **Positive Condition**: Response script writes plaintext passwords or SSNs directly to `localStorage` or `document.cookie`.
6. **Negative Condition**: Opaque hashed tokens or encrypted blobs.
7. **False Positive Scenarios**: Generic UI preference flags — filtered via sensitive keyword patterns.
8. **Why Generic 200/500 Cannot Bypass**: Analyzes JavaScript storage keys and values.
9. **Verification Strategy**: `http_response_property` — Client script inspection.
10. **Auth Context Dependency**: None.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Obfuscated client storage scripts.
14. **Final Classification**: `REAL-AUTOMATABLE`

---

### Category 7: Business Logic & Access Control (C067 – C077)

#### C067: Insecure Direct Object References (IDOR) — Numeric IDs
1. **Check ID & Name**: `C067_IDOR_Numeric_IDs` — IDOR (Numeric IDs)
2. **Category & CWE**: Category G (Business Logic), CWE-639 (Authorization Bypass Through User-Controlled Key)
3. **Detection Mechanism & Signal Type**: Sequential Identifier Increment Probing + Sensitive Property Filter
4. **Specific HTTP Requests**: Parameter substitution: `user_id=1001` -> `user_id=1002`.
5. **Positive Condition**: Probed resource returns HTTP 200 disclosing sensitive user properties (`email`, `balance`, `ssn`, `billing`) belonging to a distinct object.
6. **Negative Condition**: HTTP 401/403 Forbidden or public non-sensitive catalog data (e.g. public product listings).
7. **False Positive Scenarios**: Public e-commerce product catalog with sequential IDs (`/product?id=1002`) — strictly rejected by validating presence of sensitive private user attributes.
8. **Why Generic 200/500 Cannot Bypass**: Requires disclosure of private account/user data properties.
9. **Verification Strategy**: `AuthorizationComparisonStrategy` — Multi-tenant object boundary verification.
10. **Auth Context Dependency**: Requires authenticated session credentials for primary account (User A) to compare against User B.
11. **State / Multi-Step Dependency**: None.
12. **Browser Dependency**: None.
13. **Limitations**: Endpoints where object IDs are opaque non-sequential hashes (see C068).
14. **Final Classification**: `REAL-AUTHENTICATION-REQUIRED`

#### C068: Insecure Direct Object References (IDOR) — UUIDs
1. **Check ID & Name**: `C068_IDOR_UUIDs` — IDOR (UUIDs)
2. **Category & CWE**: Category G (Business Logic), CWE-639 (Authorization Bypass Through User-Controlled Key)
3. **Detection Mechanism & Signal Type**: Multi-Tenant UUID Cross-Account Swap
4. **Specific HTTP Requests**: Replaces User A's object UUID with User B's object UUID in API request.
5. **Positive Condition**: User A receives HTTP 200 disclosing User B's private record.
6. **Negative Condition**: HTTP 403 Forbidden.
7. **False Positive Scenarios**: Public shared resources — rejected via privacy classification.
8. **Why Generic 200/500 Cannot Bypass**: Cross-tenant authorization comparison.
9. **Verification Strategy**: `AuthorizationComparisonStrategy` — Multi-user token comparison.
10. **Auth Context Dependency**: Requires two distinct user accounts (User A token + User B UUID).
11. **State / Multi-Step Dependency**: Multi-user context.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTHENTICATION-REQUIRED`

#### C069: Broken Object Level Authorization (BOLA) in APIs
1. **Check ID & Name**: `C069_BOLA_API` — BOLA in APIs
2. **Category & CWE**: Category G (Business Logic), CWE-639 (Authorization Bypass Through User-Controlled Key)
3. **Detection Mechanism & Signal Type**: REST API Path Parameter Authorization Swap (`/api/v1/users/{id}/profile`)
4. **Specific HTTP Requests**: User A calls User B's RESTful resource path with User A's Bearer token.
5. **Positive Condition**: HTTP 200 with User B's profile data.
6. **Negative Condition**: HTTP 403 Forbidden.
7. **False Positive Scenarios**: Public profile endpoints — filtered by private data property check.
8. **Why Generic 200/500 Cannot Bypass**: Requires valid JSON response with cross-tenant data.
9. **Verification Strategy**: `AuthorizationComparisonStrategy` — Cross-tenant token replay.
10. **Auth Context Dependency**: Requires authenticated User A token.
11. **State / Multi-Step Dependency**: Multi-user context.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTHENTICATION-REQUIRED`

#### C070: Mass Assignment
1. **Check ID & Name**: `C070_Mass_Assignment` — Mass Assignment
2. **Category & CWE**: Category G (Business Logic), CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
3. **Detection Mechanism & Signal Type**: Privileged Property Injection (`is_admin: true`, `role: "admin"`, `admin: true`)
4. **Specific HTTP Requests**: POST/PUT JSON payload injecting elevated privilege attributes.
5. **Positive Condition**: Server accepts payload (HTTP 200/201) and reflects modified privileged attribute in response model.
6. **Negative Condition**: Server ignores extra fields, strips attributes, or rejects with HTTP 400.
7. **False Positive Scenarios**: API echoing all inputs without binding — verified via subsequent GET request to profile model.
8. **Why Generic 200/500 Cannot Bypass**: Validates model property binding and value persistence.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Privileged field injection replay.
10. **Auth Context Dependency**: Requires authenticated user session.
11. **State / Multi-Step Dependency**: Multi-step state (Mutate -> Inspect Model).
12. **Browser Dependency**: None.
13. **Limitations**: Blind property updates without response reflection.
14. **Final Classification**: `REAL-AUTHENTICATION-REQUIRED`

#### C071: Privilege Escalation (Vertical)
1. **Check ID & Name**: `C071_Privilege_Escalation` — Privilege Escalation
2. **Category & CWE**: Category G (Business Logic), CWE-269 (Improper Privilege Management)
3. **Detection Mechanism & Signal Type**: Low-Privilege User to Administrative Route Probing
4. **Specific HTTP Requests**: Low-privilege user token calls administrative API endpoints (`/api/admin/users`, `/api/admin/system`).
5. **Positive Condition**: Low-privilege user receives HTTP 200 with administrative data.
6. **Negative Condition**: HTTP 403 Forbidden.
7. **False Positive Scenarios**: Public routes — baseline unauthenticated check required.
8. **Why Generic 200/500 Cannot Bypass**: Dual-differential verification (Unauthenticated=401, LowPriv=200).
9. **Verification Strategy**: `AuthorizationComparisonStrategy` — Role differential verification.
10. **Auth Context Dependency**: Requires low-privilege user credentials.
11. **State / Multi-Step Dependency**: Multi-user context.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTHENTICATION-REQUIRED`

#### C072: Broken Function Level Authorization (BFLA)
1. **Check ID & Name**: `C072_Function_Access_Control` — Broken Function Level Authorization
2. **Category & CWE**: Category G (Business Logic), CWE-285 (Improper Authorization)
3. **Detection Mechanism & Signal Type**: Sensitive Administrative Action Execution under Non-Admin Role
4. **Specific HTTP Requests**: Low-privilege user invokes administrative actions (`POST /api/users/{id}/delete`, `POST /api/system/restart`).
5. **Positive Condition**: HTTP 200/204 executing function successfully.
6. **Negative Condition**: HTTP 403 Forbidden.
7. **False Positive Scenarios**: Action ignored but returns 200 — verified by object state check.
8. **Why Generic 200/500 Cannot Bypass**: Verifies action execution result.
9. **Verification Strategy**: `AuthorizationComparisonStrategy` — Action execution comparison.
10. **Auth Context Dependency**: Requires low-privilege user credentials.
11. **State / Multi-Step Dependency**: Multi-step state.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTHENTICATION-REQUIRED`

#### C073: Parameter Tampering (Price / Quantity)
1. **Check ID & Name**: `C073_Parameter_Tampering` — Parameter Tampering
2. **Category & CWE**: Category G (Business Logic), CWE-472 (External Control of Assumed-Immutable Web Parameter)
3. **Detection Mechanism & Signal Type**: Business Value Boundary Mutation (`price: 0.01`, `quantity: -1`, `discount: 100`)
4. **Specific HTTP Requests**: POST to checkout/order endpoint modifying price or negative quantity parameters.
5. **Positive Condition**: Server accepts order with tampered negative or sub-penny price (HTTP 200/201).
6. **Negative Condition**: Server recalculates price from server-side database catalog and rejects tampered values.
7. **False Positive Scenarios**: Mock checkout — verified by inspecting invoice amount in response.
8. **Why Generic 200/500 Cannot Bypass**: Requires order creation with mutated business value.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Tampered parameter replay.
10. **Auth Context Dependency**: Requires authenticated session.
11. **State / Multi-Step Dependency**: Multi-step checkout workflow.
12. **Browser Dependency**: None.
13. **Limitations**: Systems where payment gateway validates price independently.
14. **Final Classification**: `REAL-WORKFLOW-REQUIRED`

#### C074: Workflow Step Skipping
1. **Check ID & Name**: `C074_Workflow_Step_Skipping` — Workflow Step Skipping
2. **Category & CWE**: Category G (Business Logic), CWE-841 (Improper Enforcement of Behavioral Workflow)
3. **Detection Mechanism & Signal Type**: Direct Terminal Step Execution
4. **Specific HTTP Requests**: Direct POST/GET to final workflow step (e.g. `/checkout/confirm`, `/onboarding/complete`) without executing prerequisites (payment, verification).
5. **Positive Condition**: Server marks workflow complete (HTTP 200) without prerequisite step execution.
6. **Negative Condition**: Server enforces state machine and redirects to missing prerequisite step (HTTP 302 / 400).
7. **False Positive Scenarios**: Endpoint returns 200 error page — verified by order confirmation ID presence.
8. **Why Generic 200/500 Cannot Bypass**: Verifies state transition completion without prerequisites.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Out-of-order step execution.
10. **Auth Context Dependency**: Requires authenticated session.
11. **State / Multi-Step Dependency**: Multi-step state machine workflow.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-WORKFLOW-REQUIRED`

#### C075: Race Conditions / Concurrency Defects
1. **Check ID & Name**: `C075_Race_Condition` — Race Condition
2. **Category & CWE**: Category G (Business Logic), CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
3. **Detection Mechanism & Signal Type**: High-Concurrency Burst Parallelism (3-5 simultaneous socket requests)
4. **Specific HTTP Requests**: Concurrent parallel requests (e.g. coupon redemption, fund transfer, gift card claim) sent simultaneously using `asyncio.gather`.
5. **Positive Condition**: Multiple concurrent requests (>=2) succeed (HTTP 200) for a single-use token or balance deduction exceeding account limit.
6. **Negative Condition**: Exactly 1 request succeeds with HTTP 200, while all concurrent requests are serialized and rejected with HTTP 400/409 ("Already used").
7. **False Positive Scenarios**: Multi-use coupons — single request baseline tested first.
8. **Why Generic 200/500 Cannot Bypass**: Compares sequential execution (1 allowed) vs concurrent burst execution (multiple allowed).
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Synchronized socket burst.
10. **Auth Context Dependency**: Requires authenticated session token.
11. **State / Multi-Step Dependency**: Multi-request concurrent synchronization.
12. **Browser Dependency**: None.
13. **Limitations**: Highly distributed databases with eventual consistency delays > 5 seconds.
14. **Final Classification**: `REAL-WORKFLOW-REQUIRED`

#### C076: Replay Attack Vulnerability
1. **Check ID & Name**: `C076_Replay_Attack` — Replay Attack
2. **Category & CWE**: Category G (Business Logic), CWE-294 (Authentication Bypass by Capture-replay)
3. **Detection Mechanism & Signal Type**: Timestamp / Nonce Replay Probing
4. **Specific HTTP Requests**: Re-sends identical state-modifying POST request (e.g. transfer, vote) with identical nonce/timestamp after a delay.
5. **Positive Condition**: Server accepts replayed request (HTTP 200) and executes second state modification without nonce invalidation.
6. **Negative Condition**: Server rejects with HTTP 400/409 ("Nonce expired / Transaction already processed").
7. **False Positive Scenarios**: Idempotent read requests — filtered by state-modifying action validation.
8. **Why Generic 200/500 Cannot Bypass**: Verifies repeated execution of state-modifying transaction.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Replay interval verification.
10. **Auth Context Dependency**: Requires authenticated session.
11. **State / Multi-Step Dependency**: Multi-step state.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-WORKFLOW-REQUIRED`

#### C077: Missing Re-authentication for Sensitive Operations
1. **Check ID & Name**: `C077_Missing_Reauthentication` — Missing Re-authentication
2. **Category & CWE**: Category G (Business Logic), CWE-306 (Missing Authentication for Critical Function)
3. **Detection Mechanism & Signal Type**: Critical Action Execution Without Password Challenge
4. **Specific HTTP Requests**: POST to change password, email, or 2FA settings (`/api/user/change-password`, `/api/user/email`) with active session token but omitting current password.
5. **Positive Condition**: Server executes sensitive modification (HTTP 200) without requiring current password confirmation.
6. **Negative Condition**: Server rejects with HTTP 400/403 ("Current password is required to change settings").
7. **False Positive Scenarios**: Endpoints requiring re-auth returning 200 with error message — rejected by inspecting user profile update status.
8. **Why Generic 200/500 Cannot Bypass**: Verifies sensitive account attribute modification without secondary challenge.
9. **Verification Strategy**: `GenericReproducibilityStrategy` — Sensitive parameter omission replay.
10. **Auth Context Dependency**: Requires authenticated user session.
11. **State / Multi-Step Dependency**: Multi-step state.
12. **Browser Dependency**: None.
13. **Limitations**: None.
14. **Final Classification**: `REAL-AUTHENTICATION-REQUIRED`
