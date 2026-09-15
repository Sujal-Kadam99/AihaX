# AihaX Finding Quality & False-Positive Validation Gate
## Post-Real-Target Run Hardening Architecture & Specification

---

## 1. Executive Overview

The Finding Quality & False-Positive Validation Gate enforces strict separation between:
$$\text{Observed Condition} \longrightarrow \text{Security Impact} \longrightarrow \text{Reproducibility} \longrightarrow \text{Validated Vulnerability} \longrightarrow \text{Bounty Eligibility}$$

Under this invariant, AihaX **never** conflates the absence of a defensive control with an exploitable security vulnerability. Missing security headers, unauthenticated rate limiting observations without credential bypass, and directory listings exposing only benign assets are classified strictly as **Hardening Recommendations** or **Inconclusive Observations**, rather than verified vulnerabilities.

---

## 2. Core Invariants & Architectural Rules

### Invariant 1: Condition $\neq$ Vulnerability
- An observed condition (e.g. absent header) has $\text{condition\_confidence} = 1.0$.
- However, $\text{exploitability\_confidence} = 0.0$ and $\text{impact\_confidence} = 0.0$.
- Disposition is strictly `HARDENING_ONLY`.

### Invariant 2: Missing Headers Are Defense-in-Depth Only
- `C002_Missing_Security_Headers`, `C010_TLS_Configuration_Weakness` (HSTS), `C047_Missing_CSP`, `C049_Clickjacking`, and `C050_MIME_Sniffing` are **NEVER** marked as `VERIFIED` or `EXPLOITABLE`.
- Reason code is strictly `HARDENING_OBSERVED`.
- Verification status is `HARDENING_ONLY`.
- Bounty eligibility defaults to `UNKNOWN` and cannot be claimed as `ELIGIBLE` without program policy.

### Invariant 3: Multi-Attempt Rate Limiting Invariant
- Receiving HTTP 200/401 across 5 attempts without an HTTP 429 does **NOT** prove CWE-307 missing rate limiting.
- Unless automated credential stuffing, lockout bypass, or account takeover is proven, disposition is strictly `INCONCLUSIVE` (`VerificationReasonCode.RATE_LIMIT_INSUFFICIENT_EVIDENCE`), with confidence bounded at 25%.

### Invariant 4: Directory Listing Impact Invariant
- Directory indexing of benign assets (`.jpg`, `.png`, `.css`, `.js`, font files) is classified as `HARDENING_ONLY` (`VerificationReasonCode.DIRECTORY_LISTING_BENIGN`).
- It is classified as `VALIDATED` (`VerificationReasonCode.DIRECTORY_LISTING_SENSITIVE`) **only** when demonstrable exposure of sensitive files (`.env`, `.git`, `.sql`, credentials, private keys, database dumps) is verified in the proof response.

### Invariant 5: Deduplication & Header Finding Correlation
- Overlapping headers on the same endpoint are correlated under a single parent finding `C002_Missing_Security_Headers` using `parent_finding_id`.
- Child findings (`C010`, `C047`, `C049`, `C050`) link to `C002`, eliminating inflated vulnerability counts.

### Invariant 6: FACT vs [INFERENCE] Separation
- Every generated report and bug bounty package strictly separates verified technical observations from potential downstream risks:
  - **FACT:** `Strict-Transport-Security` header was absent in live response.
  - **[INFERENCE]:** The absence may reduce protection against certain network downgrade scenarios.

### Invariant 7: Bounty Eligibility Contract
- Technical validity $\neq$ bounty eligibility.
- Valid values: `ELIGIBLE`, `INELIGIBLE`, `UNKNOWN`.
- Default: `UNKNOWN`.
- False positives are strictly `INELIGIBLE`.

---

## 3. Four-Section Assessment Reporting Architecture

All generated Markdown, HTML, and PDF reports are partitioned into 4 distinct sections:

1. **Section A: Verified Security Vulnerabilities**
   - Contains only findings with disposition `VULNERABILITY` and status `VALIDATED` or `EXPLOITABLE`.
2. **Section B: Defense-in-Depth / Hardening Recommendations**
   - Contains non-exploitable configuration recommendations and defense-in-depth observations (`HARDENING_ONLY`).
3. **Section C: Inconclusive / Requires Extended Testing**
   - Contains candidate findings where evidence is insufficient to confirm or deny vulnerability (`INCONCLUSIVE`).
4. **Section D: Other Observations / Not Bounty Eligible**
   - Contains false positives, duplicates, and out-of-scope/ineligible items.

---

## 4. 14-Point Quality Gate Checklist

The `FindingQualityGate.validate_quality_gate` checklist evaluates every finding before inclusion in executive reports:

| # | Checkpoint | Invariant Requirement |
|---|---|---|
| 1 | `evidence_exists` | Proof request and response must be present |
| 2 | `evidence_belongs_to_target` | Affected URL belongs to verified target domain |
| 3 | `scope_association_exists` | Associated with valid authorized scan ID |
| 4 | `test_strategy_exists` | Associated with registered verification strategy |
| 5 | `verification_status_exists` | Explicit valid `VerificationStatus` |
| 6 | `confidence_values_consistent` | Confidence between 0 and 100, matches multidimensional scores |
| 7 | `condition_separated_from_impact` | Hardening findings do not claim confirmed impact |
| 8 | `impact_supported_by_evidence` | Confirmed impact is backed by demonstrated proof |
| 9 | `reproducibility_supported` | Proof is deterministic and reproducible |
| 10 | `exploitability_supported_if_claimed` | Hardening exploitability is strictly 0.0 |
| 11 | `fact_inference_separated` | Prefixed with `FACT:` and `[INFERENCE]:` |
| 12 | `cwe_mapping_defensible` | CSP is CWE-693, MIME is CWE-706 |
| 13 | `duplicate_correlation_applied` | Overlapping headers linked via `parent_finding_id` |
| 14 | `bounty_eligibility_not_guessed` | Defaults to `UNKNOWN`, never assumes eligible |
