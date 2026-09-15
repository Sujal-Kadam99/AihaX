# AihaX Phase 21 — Operator Guide: Controlled Vulnerability Validation

## Overview

AihaX Phase 21 provides security researchers and bug bounty hunters with an **operator-assisted, evidence-first vulnerability validation platform**. 

Instead of noisy mass scanning or dangerous autonomous exploitation, Phase 21 uses a structured, bounded scientific workflow:

```
Authorized Concrete Target
        ↓
Passive Surface Inventory
        ↓
Vulnerability Hypothesis Generation (12 Classes)
        ↓
Verification Strategy Selection
        ↓
Human Operator Review & Authorization Gate
        ↓
Explicit "APPROVE" Decision
        ↓
Safe, Controlled Verification (≤ 2 reqs, GET/HEAD/OPTIONS)
        ↓
Evidence Vault & Secret Redaction
        ↓
Differential Evidence Comparator (5 Verdicts)
        ↓
Impact Classification (Fact vs. [INFERENCE])
        ↓
Deduplication & Quality Scoring
        ↓
HackerOne-Ready Bug Bounty Report
```

---

## 1. Setting Up an Authorized Target

1. Navigate to **Targets** in the AihaX web UI or desktop app.
2. Define the program scope (e.g., `*.example.com`).
3. Create a campaign with an **exact concrete target URL** (e.g. `https://account.example.com`).
4. Set campaign mode to `bugbounty` (locked to 10 requests, 1 worker concurrency, 2 RPS rate limit).

> [!IMPORTANT]
> Wildcard domains (`*.example.com`) cannot be executed directly. Enter a specific concrete host.

---

## 2. Viewing the Validation Queue

In the **Campaigns** view, open the **Validation Queue** tab. You will see:

- **Remaining Budget Indicator**: Displays remaining request budget (out of 10) with visual progress bar.
- **Hypotheses Table**: List of candidate vulnerability hypotheses categorized by class, endpoint, parameter, estimated requests, confidence, and status.
- **Preconditions & Expected Evidence**: Detailed rationale explaining why this check is proposed and what HTTP response behavior would constitute proof.

---

## 3. Human Operator Review & Decision Workflow

Every hypothesis starts in `HUMAN_REVIEW_REQUIRED`. To act on a hypothesis:

1. Click on the hypothesis to inspect its **Preconditions**, **Proposed Strategy**, and **Expected Evidence**.
2. Select an action from the decision controls:
   - **Approve & Execute**: Authorizes safe verification and dispatches the bounded check.
   - **Reject**: Marks the hypothesis as invalid or false candidate.
   - **Skip**: Defers verification without penalty.
   - **Already Tested**: Marks hypothesis as verified in previous engagements.
   - **Request Reverification**: Retests hypothesis after target changes.
3. Every decision is cryptographically signed with a SHA-256 hash linked to the audit trail.

---

## 4. Inspecting Verification Evidence

When a verification completes, open the **Verification Evidence** view:

- **Terminal Status**: Displays `CONFIRMED`, `NOT_CONFIRMED`, `INCONCLUSIVE`, or safety block reason.
- **Differential Comparison**: Side-by-side comparison of baseline vs. verification response highlighting status code changes, reflected headers, and body deltas.
- **Secret Redaction**: Verifies that Authorization tokens, cookies, and passwords have been redacted to `[REDACTED]`.
- **SHA-256 Integrity Seal**: Displays cryptographic hashes of request and response payloads.
- **Impact Segregation**: Shows **Confirmed Impact** (observed facts) and **Potential Impact** (marked with `[INFERENCE]`).

---

## 5. Exporting Bug Bounty Reports

1. Navigate to the **Reports** section of the campaign.
2. Click **Generate HackerOne Report** (Markdown / JSON).
3. The report automatically formats:
   - Summary of Findings & Table of Affected Endpoints
   - Preconditions & Reproduction Steps
   - Baseline vs. Verification Evidence (Proof of Concept)
   - Observed Results & Factual Confirmed Impact
   - Theoretical Potential Impact (`[INFERENCE]`)
   - Actionable Remediation Guidance
   - Evidence Integrity Hashes & Scope Signatures
