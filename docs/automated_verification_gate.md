# AihaX — Fully Automated Finding Verification Gate Architecture

## Overview
The Fully Automated Finding Verification Gate removes manual operator guesswork from vulnerability analysis. Rather than forcing an operator to inspect raw HTTP requests and manually determine whether an alert is real, AihaX applies a multi-stage, deterministic evaluation pipeline to assign a canonical terminal disposition.

```text
Finding Candidate
       ↓
Check Registry Contract
       ↓
Verification Strategy
       ↓
Evidence Completeness (18-Point Check)
       ↓
False-Positive Gate (Deterministic Redirection / Header / Auth Rules)
       ↓
Reproducibility Evaluator (Differential & Baseline Consistency)
       ↓
Impact Assessment (Factual Proof vs [INFERENCE])
       ↓
Policy Eligibility Gate (Technical Reality vs Program Rules)
       ↓
Terminal Machine Disposition
```

## Canonical Terminal Dispositions
Every finding terminates in exactly one canonical state:
* `VALIDATED`: Cryptographically proven security violation with demonstrated impact.
* `EXPLOITABLE`: Verified condition with weaponization barrier breached within safe bounds.
* `DETECTED`: Observation recorded during initial check execution pending verification.
* `INCONCLUSIVE`: Anomaly or unthrottled request without sufficient technical proof.
* `HARDENING_ONLY`: Defensible security recommendation without proven exploitability (e.g. security headers).
* `FALSE_POSITIVE`: Provably negated alert (e.g. HTTP 301 to HTTPS, 401/403 access denial).
* `NOT_BOUNTY_ELIGIBLE`: Technically observable condition explicitly excluded by program scope.
* `BLOCKED_SCOPE` / `BLOCKED_AUTHORIZATION` / `BLOCKED_SAFETY` / `BLOCKED_BUDGET`: Execution halted before network dispatch.
* `VERIFICATION_ERROR`: Explicit internal engine failure, never masked as a clean scan.

## Multi-Dimensional Confidence
Rather than a single arbitrary score, confidence is computed across 5 independent axes:
1. `condition_confidence` (0.0 to 1.0): Proof that the anomaly or deviation occurred.
2. `impact_confidence` (0.0 to 1.0): Proof of technical harm or security consequence.
3. `reproducibility_confidence` (0.0 to 1.0): Consistency across multiple requests and baseline differential.
4. `exploitability_confidence` (0.0 to 1.0): Difficulty and feasibility of unauthorized state change.
5. `policy_eligibility_confidence` (0.0 to 1.0): Confidence regarding bug-bounty program inclusion.

## Safety & Invariant Guarantees
1. Zero external network traffic during verification unit tests.
2. Blocked executions (`BLOCKED_*`) are immutable.
3. Automated verification failures yield visible `VERIFICATION_ERROR`.
4. Policy unknown defaults to `UNKNOWN` and cannot become automatically `ELIGIBLE`.
