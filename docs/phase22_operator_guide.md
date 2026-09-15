# AihaX Phase 22 — Operator Guide: Real-World Authorized Exploitation & Validation

## Overview

AihaX Phase 22 provides security researchers with a controlled, evidence-first execution pipeline against explicitly authorized web targets. All actions are deterministic, non-destructive, rate-limited, and cryptographically auditable.

---

## 1. Prerequisites for Real-World Validation

Before initiating a validation run:
1. **Target Authorization**: The concrete URL (`https://account.example.com`) must be registered in the Scope Manager and marked `AUTHORIZED`.
2. **Surface Inventory**: Run passive discovery to generate baseline HTTP evidence for endpoints.
3. **Hypothesis Formulation**: Ensure hypothesis records are generated and visible in the Validation Queue with status `HUMAN_REVIEW_REQUIRED`.

---

## 2. Step-by-Step Operator Workflow

```
[Target In Scope] ➔ [Formulate Hypothesis] ➔ [Operator Review]
                                                      │
                                             (APPROVE + Ack)
                                                      ▼
[Execute 25-Step Gate] ➔ [Diff Evidence] ➔ [Cryptographic SHA-256 Chain] ➔ [HackerOne Report]
```

### Step 1: Navigating to the Real-World Validation Queue
1. Open the AihaX Web Dashboard.
2. Select your authorized campaign from the **Campaigns** view.
3. Switch to the **Real-World Validation** tab.

### Step 2: Reviewing Hypotheses & Strategies
- Review the proposed probe method, target endpoint, estimated request cost (1–2 requests), and expected differential evidence.
- Review current Campaign Budget consumption (e.g. `2/10 requests used`).

### Step 3: Authorization & Acknowledgement
1. Click **Review & Authorize** on the target hypothesis.
2. A safety confirmation modal appears displaying:
   - Target URL
   - Strategy ID & HTTP Method
   - Estimated Request Budget
3. Read the mandatory acknowledgment prompt:
   > *"I understand that this action will send a real request to the authorized target."*
4. Confirm by clicking **Authorize Real Verification**.
   - An immutable audit trail event (`RAPPR-xxxx`) is logged with a SHA-256 hash.

### Step 4: Live Execution
1. Click **Execute Real Verification**.
2. AihaX initiates the 25-step execution gate:
   - Verifies scope & destination safety.
   - Atomically reserves request budget in the ledger.
   - Sends real HTTP request via `RequestEngine` + `ScopeValidator`.
   - Captures sanitized response, computes response SHA-256 hashes.
   - Executes `DifferentialEvidenceComparator` and `RealEvidenceCorrelator`.
   - Links cryptographic SHA-256 evidence chain.
   - Automatically populates the **Live Evidence Viewer**.

### Step 5: Evidence Inspection in Live Evidence Viewer
- **Differential View**: Compare baseline vs. live verification response status, header differences, and body deltas.
- **Sanitized Headers**: Inspect request/response headers with credentials safely redacted.
- **Evidence Chain Verification**: Inspect the SHA-256 hash chain linking baseline, probe, comparison, and correlation hashes.

---

## 3. Interpreting Correlation Verdicts

| Verdict | Meaning | Action |
|---|---|---|
| **CONFIRMED** | Vulnerability proven via factual security difference | Finding created; included in report export. |
| **NOT_CONFIRMED** | Target properly enforced defenses (e.g., returned 401/403 or safe origin) | Suppressed from report; logged for learning. |
| **INCONCLUSIVE** | Target returned 5xx server error, 429 rate limit, or transport timeout | Flagged for manual re-test later. |
| **CONTRADICTED** | Response contradicted vulnerability premise | Suppressed from report. |

---

## 4. Safety & Troubleshooting

- **Target Returns 429 (Too Many Requests)**: AihaX automatically pauses and flags the result as `INCONCLUSIVE`. Do not attempt immediate re-verification.
- **Budget Exhausted (`BLOCKED_BUDGET`)**: The campaign has reached its 10-request budget ceiling. Additional requests are blocked to prevent target fatigue.
- **Scope Blocked (`BLOCKED_SCOPE`)**: The URL or redirect destination is outside the authorized scope. Verify wildcard/concrete target configuration.
