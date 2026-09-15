# Bug Bounty Platform — Phase 3 Verification Engine Architecture Audit

**Date:** 2026-08-21  
**Phase:** Phase 3 (Evidence-Based Verification Engine)  
**Status:** Audit Complete  

---

## 1. Current Finding Lifecycle
1. **Detection (Agent 3 - `VulnAgent`)**:
   - Executes registered checks (`BaseCheck`) or stub heuristics.
   - Saves initial findings to the database with `confidence` (0–100), `payload`, `proof_request`, `proof_response`, and default verdict `Inconclusive`.
2. **Verification (Agent 4 - `VerifyAgent`)**:
   - Fetches unrejected findings (`false_positive == False`).
   - Runs `_run_verification_pipeline(finding)`:
     - Awards +20% confidence if both `payload` and `proof_response` exist.
     - Deducts -40% confidence if ChromaDB contains a similar false-positive pattern.
     - Sets verdict based on static score thresholds (>= 90: `Verified`, >= 70: `Potential`, >= 40: `Inconclusive`, < 40: `Likely False Positive`).
3. **Reporting (Agent 9 - `ReportAgent` & `BugBountyReportGenerator`)**:
   - Filters findings where `verdict == "Verified"` and `false_positive == False`.
   - Formats reproduction steps, PoCs, and CWE/OWASP metadata into the report.

---

## 2. Existing Verdict States
- Current strings in `Finding.verdict`:
  - `"Verified"`
  - `"Potential"`
  - `"Inconclusive"`
  - `"Likely False Positive"`
- Boolean flag: `Finding.false_positive` (True/False).
- **Gap:** `Potential` is an ambiguous heuristic state that does not confirm whether a vulnerability actually exists. The platform lacks a formal state machine (`CANDIDATE` $\rightarrow$ `VERIFYING` $\rightarrow$ `VERIFIED` / `INCONCLUSIVE` / `FALSE_POSITIVE`).

---

## 3. Existing Evidence Model
- `EvidenceContract` in `backend/core/check_registry.py`:
  - `affected_url: str`
  - `affected_param: Optional[str]`
  - `payload: Optional[str]`
  - `proof_request: Optional[str]`
  - `proof_response: Optional[str]`
  - `confidence: int`
- **Gap:** Evidence is stored as raw, disconnected strings without unique Request IDs (`REQ-xxxxxxxx`), trace hashes, timing metadata, or baseline vs. test comparative metrics.

---

## 4. Existing Verification Behavior
- Current `VerifyAgent` does **not** make active network requests to reproduce findings.
- It relies purely on arithmetic confidence calculations and vector database similarity queries against historical false positives.
- **Critical Risk:** A finding can be marked `"Verified"` solely because an initial heuristic returned a high confidence score and arbitrary response text, without ever validating whether the defined security property holds.

---

## 5. Existing False-Positive Handling
- Relies on vector distance in ChromaDB (`false_positive_patterns`).
- If distance is < 0.3, confidence is reduced by 40%.
- If confidence drops below 40%, the finding is marked `"Likely False Positive"`.
- **Gap:** No deterministic, machine-readable failure reason codes (e.g. `AUTH_ENFORCED`, `INPUT_SANITIZED`, `NO_REPRODUCIBILITY`, `CONTRADICTORY_EVIDENCE`).

---

## 6. Existing Report Assumptions
- `BugBountyReportGenerator` correctly enforces that only `f.verdict == "Verified" and not f.false_positive` findings are included.
- `summary`, `impact_confirmed`, `impact_potential`, and `steps_to_reproduce` fallback to `"Not available from collected evidence."` when missing.
- **Property to Preserve:** The strict requirement that only `VERIFIED` findings reach Bug Bounty reports must remain completely untouched.

---

## 7. Gaps that Phase 3 Must Solve
1. **Deterministic Security Property Proving**: Findings must be verified by proving specific security properties (e.g., differential response analysis, unauthorized object access, state change verification) rather than heuristic confidence numbers.
2. **Formal Verdict & Reason Enum**: Replace arbitrary strings with `VerificationStatus` (`CANDIDATE`, `VERIFYING`, `VERIFIED`, `INCONCLUSIVE`, `FALSE_POSITIVE`) and structured `VerificationReasonCode`.
3. **Verification Contract & Registry**: Create `VerificationContract` defining required evidence, baseline/test requirements, success/failure conditions, and register strategies in `VerificationRegistry`.
4. **Integration with `RequestEngine`**: All active verification requests must pass through `RequestEngine` (subject to `ScopeValidator`, rate limits, concurrency semaphore, and secret redaction).
5. **Bounded Verification Budget**: Enforce `VerificationBudget` (`max_requests`, `max_duration_seconds`, `max_concurrency`) so verification cannot spin into unbounded loops.
6. **Non-Destructive Enforcement**: Default to non-destructive verification actions.
7. **Traceable Evidence Graph**: Link `finding_id` $\rightarrow$ `candidate_evidence` $\rightarrow$ `verification_attempt` $\rightarrow$ `request_ids` $\rightarrow$ `deterministic_verdict`.
8. **LLM Inviolability**: The deterministic verdict is absolute. No LLM output can convert `INCONCLUSIVE` or `FALSE_POSITIVE` into `VERIFIED`, or vice-versa.
