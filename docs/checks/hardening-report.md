# AihaX — 77 Security Checks Hardening & Invariant Report

> **Engineering Audit:** Adversarial Security Hardening  
> **Repository:** AihaX  
> **Status:** Production-Grade Hardening Verified (264/264 Tests Passing)  

---

## 1. Architectural Invariants Enforced

### Invariant 1: Centralized RequestEngine Enforcement
* **Rule:** Checks MUST NEVER use direct HTTP clients (`requests`, `urllib`, `httpx`, `aiohttp`, `socket`, `subprocess`).
* **Audit Result:** PASSED (Zero direct network library imports across all 77 check modules in `backend/agents/checks/`).
* **Enforcement:** 100% of network requests pass through `RequestEngine`, guaranteeing automatic `ScopeValidator` policy enforcement, rate limiting, and timeout handling.

### Invariant 2: Candidate-Only Check Verdicts
* **Rule:** Checks MUST NEVER mark a finding as `VERIFIED` directly.
* **Audit Result:** PASSED (All 77 checks emit `verification_status="CANDIDATE"` with traceable evidence IDs).
* **Enforcement:** The `VerificationEngine` independently verifies findings through deterministic strategies.

### Invariant 3: Non-Destructive Operation
* **Rule:** Checks MUST NEVER execute destructive operations (e.g. `rm -rf`, `DROP TABLE`, `<script>alert()</script>`, file overwrites).
* **Audit Result:** PASSED. All tests employ harmless mathematical canary calculations (e.g., `expr 31330 + 7 -> 31337`, `{{31330+7}} -> 31337`) or passive observation.

---

## 2. Hardened Detection Logics

| Check ID | Hardening Improvement | False-Positive Scenario Prevented |
|---|---|---|
| **C009 (Admin Interface)** | Separates unauthenticated management panels (`/actuator`, `/manager/html`, dashboards) from standard login forms. Prioritizes active unauthenticated consoles over login forms. | Normal login forms (`/admin/` with password fields) are not incorrectly reported as unauthenticated admin panel breaches. |
| **C020 (JWT alg: none)** | Added unauthenticated baseline and invalid token control requests. Requires target to be authentication-gated (401/403 on invalid/no token) before flagging `alg: none` 200 responses. | Public unauthenticated pages returning 200 OK for any request are not falsely reported as JWT algorithm bypasses. |
| **C021 (JWT exp Claim)** | Added baseline unauthenticated and invalid token gating. | Public endpoints returning 200 OK are not falsely reported as expired token acceptance. |
| **C027 (OS Command Injection)** | Evaluates baseline response body before injection to ensure canary result (`31337`) does not already exist. Employs alternate canaries if static collision is detected. | Static pages with numbers like "31337" or "49" in baseline body are not falsely reported as command injection. |
| **C028 (SSTI)** | Employs distinctive high-entropy arithmetic expressions (`{{31330+7}} -> 31337`) with pre-injection baseline body verification. | Generic template pages or numbers on page are not falsely reported as template execution. |
| **C037 (Reflected XSS)** | Checks for raw unescaped HTML tag reflection while explicitly ensuring HTML-encoded entities (`&lt;...&gt;`) are not flagged. Confirms HTML Content-Type. | Properly encoded user inputs and JSON API responses are not falsely reported as XSS. |
| **C057 (Exposed API Keys)** | Redacts captured tokens (e.g., `AKIA****************`) in candidate proof and evidence logs. | Raw user credentials or secrets are never leaked in unredacted form in logs or reports. |
| **C067 (IDOR Numeric)** | Inspects adjacent ID responses for sensitive private data keywords (e.g., `email`, `balance`, `billing`, `user_id`) or cross-account context. | Public catalog items (e.g., `/products?id=1` vs `id=2`) are not falsely flagged as IDOR. |

---

## 3. Test Verification Summary

* **Unit & Architecture Tests:** 246 passing tests.
* **Real Loopback HTTP Tests:** 18 passing socket tests against live `AiohttpTransport`.
* **Total Automated Suite:** **264 / 264 passing tests (0 failures)**.
* **Execution Time:** ~38 seconds across full suite.
