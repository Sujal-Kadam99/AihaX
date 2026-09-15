# AihaX Phase 23 — Hard Security Invariants & Fail-Closed Gates

## Executive Summary
AihaX Phase 23 delivers Advanced Authorized Vulnerability Research & Multi-Step Validation for concrete bug-bounty and security assessment targets. All execution is strictly bounded, authorization-governed, read-only, auditable, and fail-closed.

---

## 1. Core Security Invariants

### 1.1 Authorization & Human-in-the-Loop Binding
- **Default Deny / Human Review Required:** Every generated hypothesis and multi-step validation plan defaults to `HUMAN_REVIEW_REQUIRED`.
- **Explicit Approval Gating:** Execution of any validation plan strictly requires an approved `operator_approval_id` and verified `operator_id`.
- **Non-Transferable Approval:** Resuming a paused or stopped validation plan requires fresh operator approval.
- **Fail-Closed Missing Credentials:** If authorization or approval records cannot be resolved, execution is blocked (`BLOCKED_AUTHORIZATION`).

### 1.2 Safe HTTP Method Whitelisting
- **Permitted Methods:** `GET`, `HEAD`, `OPTIONS` only.
- **Strictly Prohibited Methods:** `POST`, `PUT`, `DELETE`, `PATCH`, `CONNECT`, `TRACE`, `PROPFIND`, `MKCOL`, etc. Any occurrence immediately triggers `BLOCKED_METHOD`.

### 1.3 Strict Request & Concurrency Budgeting
- **Request Budget Hard Cap:** Maximum 10 HTTP requests per validation plan execution (`LOCKED_MAX_BUDGET = 10`).
- **Rate Limit Hard Cap:** Maximum 2.0 Requests Per Second (`LOCKED_MAX_RATE_RPS = 2.0`).
- **Concurrency Hard Cap:** Maximum concurrency of 1 (`LOCKED_MAX_CONCURRENCY = 1`). Parallel worker dispatch is structurally blocked.

### 1.4 Scope & Destination Safety (Anti-SSRF / Anti-Pivot)
- **Concrete Targets Only:** Wildcard domains (`*.example.com`) are permitted in program scopes for passive reasoning, but strictly prohibited as executable targets (`BLOCKED_SCOPE`).
- **Prohibited Service Ports:** Ports 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 110 (POP3), 143 (IMAP), 445 (SMB), 1433 (MSSQL), 1521 (Oracle), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL), 5601 (Kibana), 6379 (Redis), 9200 (Elasticsearch), 11211 (Memcached), 27017 (MongoDB) are strictly blocked (`BLOCKED_DESTINATION`).
- **Private Subnet / Cloud Metadata Protection:** Requests targeting RFC1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local metadata (`169.254.169.254`, `metadata.google.internal`) fail closed in production.

### 1.5 Sensitive Data Sanitization & Redaction
- **Header Redaction:** Headers including `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `API-Key`, `Token`, `X-Auth-Token`, `Session` are automatically redacted as `[REDACTED]` prior to persistence, auditing, or reporting.

### 1.6 Cryptographic Evidence Integrity & Audit Trail
- **SHA-256 Chained Attestation:** Validation observations, scope snapshots, operator approvals, hypotheses, plans, and reproductions form an immutable SHA-256 Merkle chain.
- **Tamper Evidence:** Alteration of any historical observation or link invalidates the root chain head deterministically.
- **FACT vs [INFERENCE] Separation:** Finding deliverables strictly segregate directly observed empirical HTTP facts from theoretical impact inferences.
