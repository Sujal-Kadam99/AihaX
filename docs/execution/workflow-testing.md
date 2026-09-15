# Multi-Step Workflow & Business Logic Testing

## 1. Overview

Business logic and transaction flow checks (such as C074 Workflow Step Bypass, C075 Race Condition / Concurrency Flaws, C076 Replay Attacks, and C077 Missing Re-authentication) require multi-stage request coordination.

---

## 2. Supported Workflow Check Patterns

### 2.1 Workflow Step Bypass (C074)
- **Target**: Multi-step operations (e.g. `Step 1: Input Data` $\rightarrow$ `Step 2: Payment` $\rightarrow$ `Step 3: Fulfillment`).
- **Execution Flow**:
  1. The workflow engine maps the sequential stages from crawled forms or OpenAPI specifications.
  2. The check attempts to directly invoke `Step 3` or `Finalize` without completing `Step 2`.
  3. If the backend accepts the transition and fulfills the request $\rightarrow$ Workflow bypass candidate confirmed.

### 2.2 Race Condition / Concurrency Flaws (C075)
- **Target**: Balance deductions, coupon redemptions, gift card applications, or vote tallies.
- **Execution Flow**:
  1. Captures baseline balance / resource state.
  2. Sends $N$ (e.g., $N=5$) concurrent requests to the redeem endpoint synchronized using `asyncio.gather` within a single event loop tick.
  3. Evaluates balance diff: If single-use coupon is redeemed $>1$ times or negative balance is achieved $\rightarrow$ Race condition candidate confirmed.

### 2.3 Replay Attacks (C076)
- **Target**: Financial transfer endpoints, password reset tokens, or one-time verification tokens.
- **Execution Flow**:
  1. Executes primary transaction.
  2. Replays identical signed payload / token immediately after success.
  3. If backend processes transaction twice with identical nonce $\rightarrow$ Replay vulnerability candidate confirmed.

### 2.4 Missing Re-Authentication (C077)
- **Target**: Sensitive account settings (email change, password change, 2FA deactivation).
- **Execution Flow**:
  1. Attempts email/password update request without providing the current password in the payload.
  2. If backend updates sensitive account attributes without password re-entry $\rightarrow$ Candidate confirmed.
