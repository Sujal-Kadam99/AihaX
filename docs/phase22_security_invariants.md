# AihaX Phase 22 — Security & Execution Invariants

## Master Threat Model & Safety Guarantees

Phase 22 upgrades AihaX into a real-world, operator-authorized vulnerability exploitation and evidence-backed validation platform. To ensure zero collateral damage, zero unauthorized activity, and cryptographic integrity across all operations, the following hard security invariants are strictly enforced at every layer of the system.

---

### 1. Concrete Target Gating & Scope Authority

- **Single Concrete Target Invariant**:
  - Every real-world validation campaign operates against exactly ONE concrete, fully-qualified URL (e.g., `https://account.example.com`).
  - Wildcards (`*.example.com`) are treated strictly as scope boundaries and fail closed with `BLOCKED_SCOPE` if submitted as active execution targets.
  - Multi-target campaigns, CIDR blocks, or unbounded IP ranges are rejected before any network traffic is scheduled.

- **Re-Validation Pre-Flight**:
  - Immediately before dispatching any HTTP request, `ScopeValidator.validate_url_in_scope()` performs real-time validation against authorized program assets and excluded subnets.

---

### 2. Destination Safety & SSRF Immunity

- **Zero Loopback / RFC1918 / Metadata Egress**:
  - Loopback IPs (`127.0.0.0/8`, `localhost`, `::1`) are unconditionally rejected.
  - RFC1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and carrier-grade NAT ranges are rejected.
  - Cloud metadata IP endpoints (`169.254.169.254`, `metadata.google.internal`) are blocked at the DNS resolution and socket connection levels.
  - Non-standard port probing (e.g. ports 22, 25, 3306, 5432, 6379, 27017) is forbidden.

- **Safe Redirect Execution**:
  - HTTP redirects are not followed blindly. Each intermediate redirect destination is independently evaluated by `validate_destination_safety()` before following.

---

### 3. Human Review & Operator Authorization Gate

- **Zero Autonomous Exploitation**:
  - Every vulnerability hypothesis defaults to status `HUMAN_REVIEW_REQUIRED`.
  - The system CANNOT dispatch real verification requests autonomously.
  - Explicit human approval via `RealWorldExploitExecutor.log_operator_approval()` is mandatory prior to live execution.

- **Cryptographic Authorization Binding**:
  - The approval record binds:
    - `campaign_id`
    - `hypothesis_id`
    - `strategy_id`
    - `target`
    - `operator_id`
    - Exact acknowledgement text: *"I understand that this action will send a real request to the authorized target."*
  - The approval event is cryptographically hashed with SHA-256 and chained to the previous audit event.

---

### 4. Hard Production Rate & Concurrency Constraints

| Parameter | Production Value | Enforcement Mechanism |
|---|---|---|
| **Max Campaign Budget** | $\le 10$ HTTP Requests | `VerificationBudgetLedger` Atomic Check |
| **Max Strategy Budget** | $\le 2$ HTTP Requests | `VerificationStrategyEngine` Cap |
| **Max Concurrency** | Exactly 1 | `asyncio.Semaphore(1)` Lock |
| **Rate Limit** | $\le 2.0$ RPS | Token Bucket Leaky Limiter |
| **Allowed Methods** | `{GET, HEAD, OPTIONS}` | `LOCKED_ALLOWED_METHODS` Whitelist |
| **Mutation Methods** | Strictly Forbidden | Zero POST / PUT / PATCH / DELETE |

---

### 5. Multi-Layer Evidence Redaction & Contract Vaulting

- **Credential Redaction**:
  - All Authorization headers (`Bearer`, `Basic`, API keys), Cookie sessions, `Set-Cookie`, `X-CSRF-Token`, and `Proxy-Authorization` headers are sanitized to `[REDACTED]` prior to persistent storage.
- **Body Redaction**:
  - Private RSA/EC keys, password strings, and raw tokens in response bodies are stripped with regex sanitizers before writing to the database.
- **Tamper-Evident SHA-256 Chain**:
  - Each verification run computes:
    $$\text{ChainHash} = \text{SHA256}(\text{PrevChainHash} : \text{CampaignID} : \text{RunID} : \text{BaseHash} : \text{VerifHash} : \text{CompHash} : \text{CorrHash})$$
  - Any modification to baseline, verification, comparison, or correlation results invalidates the cryptographic chain.

---

### 6. Zero Network Testing Isolation Guarantee

- All automated unit tests and master certification scripts execute exclusively against `MockTransport` and in-memory SQLite.
- External network bytes are physically impossible during test runs, preventing accidental traffic to external networks during CI/CD.
