# AihaX — Finding Lifecycle State Machine

## Finding Lifecycle Overview

Findings in AihaX transition through a strict, deterministic state machine implemented in `backend/services/finding_deduplicator.py`.

---

## 1. Lifecycle States

```text
DISCOVERED
    ↓
CANDIDATE
    ↓
VERIFYING
    ↓
VERIFIED  ───────────────→  DEDUPLICATED  ───────────────→  REPORTABLE
    ↓                              ↓                              ↓
REJECTED / INCONCLUSIVE        REJECTED                       REJECTED
```

### State Definitions:
1. **`DISCOVERED`**: Initial trigger identified during heuristic or path scanning.
2. **`CANDIDATE`**: Check emitted candidate evidence (`CheckResult`).
3. **`VERIFYING`**: Active verification strategy running via `VerificationEngine`.
4. **`VERIFIED`**: Deterministic verification strategy succeeded.
5. **`DEDUPLICATED`**: Finding grouped by location fingerprint and evidence merged.
6. **`REPORTABLE`**: Verified finding formatted for Bug Bounty export.
7. **`REJECTED`**: Marked as False Positive or contradicted by baseline.
8. **`INCONCLUSIVE`**: Insufficient evidence to prove exploitability without further manual testing.
9. **`NOT_APPLICABLE`**: Required capability or prerequisite was unavailable.

---

## 2. Invariant Rules

- **No Detector Verification**: Checks can ONLY emit `CANDIDATE`. A check detector can NEVER mark a finding as `VERIFIED`.
- **No LLM Verdict Overrides**: Verification verdicts are strictly deterministic. An LLM cannot promote an inconclusive finding to verified.
- **Reporting Gate**: Only findings in `VERIFIED` and `REPORTABLE` state reach `BugBountyReportGenerator`.
