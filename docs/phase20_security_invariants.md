# AihaX Phase 20 — Security & Hunting Invariants Specification

## Status: Certified & Active

This document establishes the inviolable security and operational invariants of **AihaX Phase 20: Real-World Hunting Intelligence, Evidence Learning & Operator Optimization**. All components, automated engines, and operator workflows must strictly enforce and comply with these rules.

---

## 1. Locked Production Profile & Execution Budget

To prevent excessive server load, service degradation, or aggressive scanning flags on target bug bounty programs:

1. **Request Budget Hard Ceiling**: Maximum **10 requests** per reconnaissance/hunting campaign (`LOCKED_PRODUCTION_BUDGET = 10`). Under no circumstance may any automated agent exceed this allocation.
2. **Concurrency Ceiling**: Strict single-thread execution (`LOCKED_MAX_CONCURRENCY = 1`). Concurrency > 1 is prohibited in production hunting mode.
3. **Rate Limiting**: Hard ceiling of **2 requests per second** (`LOCKED_RATE_LIMIT_RPS = 2.0`). Bursting beyond 2 RPS is strictly blocked by token-bucket rate limiters.
4. **Safe HTTP Methods Only**: Only non-destructive idempotent HTTP methods (`GET`, `HEAD`, `OPTIONS`) are permitted in automated hunting checks (`LOCKED_ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS"}`). Zero `POST`, `PUT`, `DELETE`, or `PATCH` requests are permitted during automated hunting reconnaissance without explicit operator intervention.
5. **Zero Destructive Actions**: Fuzzing, large brute-forcing, high-volume directory enumeration, and intrusive parameter tampering are hard-prohibited.

---

## 2. Target Lifecycle & Concrete Target Gating

1. **Exact Concrete URL Target Only**: Campaigns require a concrete, fully qualified target URL (e.g. `https://account.xiaomi.com`).
2. **Wildcard Execution Block**: Wildcard scope specifications (e.g., `*.xiaomi.com`) serve strictly as authorization boundaries. A wildcard target URL cannot be directly executed or dispatched and transitions the campaign to `WAITING_FOR_TARGET`.
3. **No Automatic Target Hunting**: The system never expands scope, hunts for new subdomains automatically, or launches tasks against discovered surfaces without human review and selection.
4. **SSRF & Private Network Boundary**: Automated destination validation strictly blocks loopback (`127.0.0.1`, `localhost`, `::1`), private RFC1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local/cloud metadata (`169.254.169.254`), and custom non-standard ports.

---

## 3. Passive Surface Inventory & Memory Ingestion

1. **Zero Active Scanning for Inventory**: Surface inventory entries (endpoints, parameters, headers, auth states) are populated **100% passively** from in-memory responses during authorized checks. No directory brute-forcing or active endpoint scraping is performed.
2. **Deterministic Normalization**: All observed endpoints are normalized (stripping query parameters, normalizing URL casing, deduplicating parameter sets) into canonical paths.
3. **Target Boundary Isolation**: Surface inventory entries are isolated strictly to their owning concrete target domain.

---

## 4. Negative Evidence Non-Vulnerability Tracking

1. **Zero Vulnerability Hallucination**: When a security check fails to identify a vulnerability or observes a safe state (e.g. valid HSTS header, proper CORS isolation, TLS redirect), it records a **Negative Evidence Record**.
2. **Non-Vulnerability Persistence**: Negative evidence is persisted with complete request/response SHA-256 hashes, scope snapshot hashes, and failure rationales. Negative evidence never manufactures a `Finding` record.
3. **Negative Evidence Suppression**: Once negative evidence is established for a check on a target, future plan generation suppresses the check to prevent wasteful duplicate requests.
4. **Scope Hash Invalidation**: If the scope snapshot hash changes, negative evidence suppression is invalidated and checks are re-evaluated safely.

---

## 5. Cross-Assessment Memory & Evidence Learning

1. **Domain-Level Pattern Extraction**: Memory records aggregate check efficacy and utility metrics keyed by normalized root domain (e.g., `xiaomi.com`).
2. **Clamped Modifier Bounds**: Prioritization modifiers derived from historical learning are strictly bounded between `[-0.20, +0.20]`. This ensures cold-start baseline checks are never completely starved and no single check permanently monopolizes execution order.
3. **No Scope Expansion via Memory**: Historical memory records cannot alter or widen the campaign's authorized target scope.
4. **Cold Start Determinism**: Unknown targets default to prior utility `0.50` with modifier `0.00`.

---

## 6. Finding Quality Scoring & Strict Reporting Gates

1. **Multi-Factor Quality Metric**: Every candidate finding is evaluated across six deterministic dimensions:
   - Evidence Completeness (Weight: 0.25)
   - Reproducibility (Weight: 0.20)
   - Impact Confirmation (Weight: 0.20)
   - Cryptographic Integrity Hashes (Weight: 0.15)
   - Scope Validity (Weight: 0.10)
   - Structural Uniqueness (Weight: 0.10)
2. **Categorical Quality Bands**:
   - **Band A (Score >= 0.90)**: Outstanding proof, reproducible, confirmed impact, full hashes.
   - **Band B (0.75 <= Score < 0.90)**: Strong evidence, reproducible.
   - **Band C (0.60 <= Score < 0.75)**: Acceptable minimal evidence.
   - **Band D (Score < 0.60)**: Weak, speculative, or unverified findings.
3. **Strict Reportability Gate**: Only findings in **Band A, B, or C** that are verified, unique, in-scope, and operator-approved can be included in generated reports. Band D findings are strictly non-reportable.
4. **Fact vs. Inference Separation**: Markdown and PDF reports strictly demarcate `Confirmed Impact (Observed Fact)` from `Potential Impact (Theoretical Risk)` with mandatory `[INFERENCE]` tagging. Zero placeholder text (`TODO`, `TBD`, `[REPLACE]`) is permitted.

---

## 7. Operator Decision Gate & Cryptographic Audit Trail

1. **Zero Autonomous Exploitation / Submission**: All hunting recommendations enforce `authorization_status = "HUMAN_REVIEW_REQUIRED"`. No recommendation can be executed without explicit operator review and confirmation.
2. **Operator Decision Actions**: The UI and API strictly support five audited decisions:
   - `APPROVE`: Human verified and approved for execution within budget.
   - `REJECT`: Human rejected recommendation as irrelevant or low-value.
   - `SKIP`: Human deferred recommendation for future consideration.
   - `ALREADY_TESTED`: Human confirmed target was already tested out-of-band.
   - `REQUEST_REVERIFICATION`: Human requested re-verification under strict parameters.
3. **Cryptographic SHA-256 Audit Chain**: Every decision produces an immutable audit record linked to the prior event's SHA-256 hash (`previous_event_hash -> event_hash`), creating a tamper-evident audit ledger.
