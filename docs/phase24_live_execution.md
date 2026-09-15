# AihaX Phase 24 — Live Execution & Security Boundary

## Overview
The `VulnerabilityExecutionEngine` executes tests against real target applications while maintaining fail-closed security controls, cryptographic evidence chaining, and human approval gating.

---

## Execution Modes
1. **PLAN_ONLY (Default):**
   - Evaluates attack surface and generates matrix and hypotheses.
   - Dispatches zero network requests.
   - Returns result with `execution_mode = "PLAN_ONLY"` and explanations.
2. **SIMULATION:**
   - Evaluates hypotheses against simulated / mock transports.
   - Used for zero-network unit test validation.
3. **AUTHORIZED_LIVE:**
   - Requires concrete target, ScopeValidator approval, destination safety, and explicit human operator approval (`operator_id` + `operator_approval_id`).
   - Dispatches requests via `RequestEngine`.

---

## Central Network Boundary
- Live HTTP/HTTPS traffic MUST flow through `RequestEngine`.
- Direct imports or calls to `requests`, `aiohttp`, `httpx`, `urllib`, `socket`, or direct subprocess networking are forbidden and statically checked.
- Anti-SSRF destination safety blocks connections to loopback (`127.0.0.1`), RFC1918 private subnets, cloud metadata (`169.254.169.254`), and prohibited ports.

---

## Rate & Concurrency Limits
- Maximum concurrency: `1`
- Maximum rate: `<= 2 requests/sec`
- Conservative request budget per hypothesis: `1` to `5` requests.

---

## Cryptographic Evidence & Secret Redaction
- Produces `VulnerabilityExecutionEvidence` containing:
  - `baseline_hash` (SHA-256)
  - `test_hash` (SHA-256)
  - `evidence_hash` (SHA-256 computed over full differential outcome)
- Sensitive headers and credentials (`Authorization`, `Cookie`, `X-API-Key`, OTPs, passwords) are redacted prior to hashing and persistence.
