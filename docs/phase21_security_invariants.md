# AihaX Phase 21 — Security & Validation Invariants Specification

## Status: Certified & Active

This document establishes the inviolable security, safety, and operational invariants of **AihaX Phase 21: Controlled Exploit Validation & Vulnerability Discovery Pipeline**. All components, automated executors, cryptographic contracts, and operator workflows must strictly enforce and comply with these rules.

---

## 1. Locked Production Profile & Verification Budget

To prevent denial of service, service degradation, or excessive volume against authorized bug bounty targets:

1. **Verification Budget Hard Ceiling**: Strict maximum **10 requests** per verification campaign (`LOCKED_PRODUCTION_BUDGET = 10`). Any attempt to exceed 10 requests immediately raises `BudgetExhaustedException` and halts execution.
2. **Per-Hypothesis Budget Limit**: Verification experiments are strictly bounded between 1 and 2 requests (`estimated_requests <= 2`).
3. **Concurrency Ceiling**: Strict single-thread execution (`LOCKED_MAX_CONCURRENCY = 1`). Concurrency > 1 is prohibited in production verification mode.
4. **Rate Limiting**: Hard ceiling of **2 requests per second** (`LOCKED_RATE_LIMIT_RPS = 2.0`). Bursting beyond 2 RPS is blocked by token-bucket rate limiters.
5. **Safe HTTP Methods Only**: Only non-destructive, read-only HTTP methods (`GET`, `HEAD`, `OPTIONS`) are permitted in automated verification checks (`LOCKED_ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS"}`). Zero `POST`, `PUT`, `DELETE`, or `PATCH` requests are permitted.
6. **Zero Destructive Exploitation**: No autonomous SQL injection exploitation, no remote code execution payload triggering, no mass data exfiltration, no lateral movement, and no wordlist fuzzing.

---

## 2. Concrete Target Scope & SSRF Destination Safety

1. **Exact Concrete URL Target Only**: Verification experiments execute only against concrete target URLs (e.g. `https://account.example.com`).
2. **Wildcard Target Execution Block**: Wildcard scope definitions (e.g. `*.example.com`) are authorization boundaries only. Wildcard targets cannot be executed and fail closed with `BLOCKED_SCOPE`.
3. **SSRF & Private Network Boundary**: Automated destination validation strictly blocks loopback (`127.0.0.1`, `localhost`, `::1`), private RFC1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), cloud metadata endpoints (`169.254.169.254`), and non-standard ports before any network connection is attempted.
4. **Central Request Engine Enforcement**: All verification HTTP requests must route strictly through `RequestEngine` and `ScopeValidator`. Direct raw sockets (`socket`, `urllib.request`, `requests`, `httpx` outside `RequestEngine`) are prohibited.

---

## 3. Human Operator Review & Authorization Gate

1. **Default Status**: Every generated vulnerability hypothesis defaults strictly to `authorization_status = "HUMAN_REVIEW_REQUIRED"`.
2. **Explicit APPROVE Decision Required**: The verification engine cannot execute any verification experiment unless an explicit operator decision of `APPROVE` has been logged.
3. **Decision Types**: Permitted operator decisions are strictly enumerated:
   - `APPROVE`: Authorize safe bounded verification execution.
   - `REJECT`: Mark hypothesis invalid or not applicable.
   - `SKIP`: Defer testing without rejecting.
   - `ALREADY_TESTED`: Mark hypothesis as previously verified.
   - `REQUEST_REVERIFICATION`: Request re-execution after target updates.
4. **Audit Hash Chaining**: Every operator decision is recorded in `hypothesis_decisions` with a deterministic SHA-256 event hash linking to the campaign's previous decision hash:
   $$\text{event\_hash} = \text{SHA-256}(\text{prev\_hash} \mid \text{decision\_id} \mid \text{operator\_id} \mid \text{campaign\_id} \mid \text{hypothesis\_id} \mid \text{strategy\_id} \mid \text{decision} \mid \text{timestamp} \mid \text{rationale})$$

---

## 4. Evidence Contract & Sensitive Secret Redaction

1. **Strict Secret Redaction Before Vault Storage**: Sensitive credentials, tokens, session cookies, and API keys are redacted before persistence in `verification_evidence`:
   - Sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `api-key`, `token`, `password`) $\rightarrow$ `[REDACTED]`
   - Sensitive body patterns (Bearer tokens, JWTs, JSON secret keys, session cookies) $\rightarrow$ `[REDACTED]`
2. **Cryptographic SHA-256 Evidence Hashing**: Every raw request and response is signed with a 64-character hexadecimal SHA-256 hash. Any tampering with evidence invalidates the evidence contract.
3. **Scope & Verifier Version Binding**: Every evidence record binds `scope_snapshot_hash`, `verifier_version`, and `timestamp` for complete tamper-evident auditability.

---

## 5. Differential Evidence Comparator

1. **Deterministic Response Comparison**: The comparator analyzes baseline vs verification response pairs across status codes, security headers, normalized body structure, and error signatures.
2. **Categorical Verdicts**:
   - `SAME`: Responses are structurally and semantically identical.
   - `NON_SECURITY_DIFFERENCE`: Differences are limited to dynamic tokens, timestamps, or benign headers.
   - `SECURITY_RELEVANT_DIFFERENCE`: Responses exhibit security-relevant divergence (e.g. CORS origin reflection, 401/403 $\rightarrow$ 200 transition, open redirect Location header).
   - `DIFFERENT`: Structural divergence without conclusive vulnerability proof.
   - `INCONCLUSIVE`: Transport timeout, network failure, or 5xx server error.
3. **Dynamic Token & Timestamp Normalization**: Dynamic CSRF tokens, nonces, timestamps, and request IDs are normalized into canonical tokens (`[TIMESTAMP]`, `[TOKEN]`) to prevent false differences.

---

## 6. Impact Segregation: Concrete Facts vs. [INFERENCE] Potential

1. **Confirmed Impact (Observed Fact)**: Must describe only directly observed HTTP response facts (e.g. "Server reflected arbitrary Origin header and permitted cross-origin credentials").
2. **Potential Impact (Theoretical Risk)**: Must be prefixed with mandatory `[INFERENCE]` tag (e.g. "[INFERENCE] An attacker could host a malicious webpage to steal user profile data").
3. **Zero Impact Inflation**: Reports strictly separate observed evidence from theoretical worst-case exploitation.

---

## 7. Finding Quality Gate & Deduplication

1. **Multi-Factor Quality Scoring**: Findings must achieve a quality score $\ge 0.70$ (Band A $\ge 0.85$, Band B $\ge 0.70$) to be marked reportable.
2. **Location-Based Fingerprinting**: Fingerprints are calculated deterministically:
   $$\text{fingerprint} = \text{SHA-256}(\text{vuln\_type} \mid \text{normalized\_endpoint} \mid \text{param\_location} \mid \text{category})$$
3. **Zero Unapproved / Duplicate Reports**: Unapproved findings, duplicate findings, and findings below quality threshold are excluded from generated reports.
4. **No Autonomous Submission**: Reports are prepared for human operator review in standard Markdown / HackerOne format. AihaX never automatically submits findings to third-party bug bounty platforms without human approval.
