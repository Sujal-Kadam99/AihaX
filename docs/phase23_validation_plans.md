# AihaX Phase 23 — Multi-Step Validation Plans & Strategies

## Overview
Phase 23 introduces structured, deterministic multi-step validation plans tailored to 12 distinct web vulnerability classes.

---

## Supported Vulnerability Classes & Step Sequences

### 1. CORS Misconfiguration (`CORS`)
- **Step 1:** Baseline GET inquiry on API endpoint with standard headers.
- **Step 2:** Origin header probe with untrusted test origin (`https://evil.com`).
- **Step 3:** Preflight `OPTIONS` probe verifying `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials: true`.

### 2. IDOR / Broken Object Level Authorization (`IDOR_BOLA`)
- **Step 1:** Baseline GET inquiry accessing primary user resource.
- **Step 2:** Differential probe accessing adjacent entity identifier without tenant escalation.
- **Step 3:** Differential header/response comparison evaluating object leakage.

### 3. Open Redirect (`OPEN_REDIRECT`)
- **Step 1:** Baseline GET inquiry on navigation endpoint.
- **Step 2:** Navigation parameter probe containing non-whitelisted destination URL.
- **Step 3:** Inspection of HTTP 30x Location header determinism.

### 4. Security Headers (`SECURITY_HEADERS`)
- **Step 1:** Baseline GET inquiry evaluating `Strict-Transport-Security`, `Content-Security-Policy`, and `X-Frame-Options`.

### 5. Access Control & Authorization (`ACCESS_CONTROL`, `API_AUTHORIZATION`)
- **Step 1:** Baseline authenticated/anonymous inquiry.
- **Step 2:** Role boundary differential probe across safe HTTP methods.

### 6. Authentication & Session Security (`AUTHENTICATION`, `SESSION_SECURITY`)
- **Step 1:** Baseline login/token inquiry.
- **Step 2:** Inspection of `Set-Cookie` flags (`Secure`, `HttpOnly`, `SameSite`).

### 7. Information Disclosure (`INFORMATION_DISCLOSURE`)
- **Step 1:** Safe GET probe inspecting status codes and error page stack trace indicators.

### 8. URL Parameter & Cache Behavior (`URL_PARAMETER_BEHAVIOR`, `CACHE_BEHAVIOR`, `INPUT_HANDLING`)
- **Step 1:** Baseline cache/parameter inquiry.
- **Step 2:** Benign variation differential comparison.
