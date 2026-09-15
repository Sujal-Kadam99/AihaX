# AihaX — Automated Verification Walkthrough & Operator Guide

## Overview
This walkthrough demonstrates how AihaX automatically determines finding verification without operator guesswork.

### Scenario 1: Missing Security Headers
- **Observed Behavior**: `GET https://target.local/` returns 200 OK without `Content-Security-Policy`.
- **Automated Verification Action**:
  - `ReproducibilityEvaluator`: Consistency 1.0.
  - `AutomatedFindingVerifier`: Dispatches to Header Strategy.
  - Exploitability is 0.0, impact is 0.0.
  - Assigned Disposition: `HARDENING_ONLY`.
  - Assigned Bounty Eligibility: `INELIGIBLE`.

### Scenario 2: Sensitive Directory Listing
- **Observed Behavior**: `GET https://target.local/backup/` exposes `.env` and `database.sql`.
- **Automated Verification Action**:
  - `FalsePositiveGate`: Confirms sensitive credentials exposed.
  - `ReproducibilityEvaluator`: Consistent status 200 with sensitive body match.
  - Assigned Disposition: `VALIDATED`.
  - Assigned Bounty Eligibility: `ELIGIBLE` (if covered by policy).

### Scenario 3: Port 80 Redirect
- **Observed Behavior**: `GET http://target.local/` returns 301 to `https://target.local/`.
- **Automated Verification Action**:
  - `FalsePositiveGate`: Rule `FP-RULE-TRANSPORT-REDIRECT` triggers.
  - Assigned Disposition: `FALSE_POSITIVE`.
  - Confidence reduced to 10%, finding marked rejected.
