# Phase 18: Finding Verification Hardening & HackerOne-Ready Reporting

## Overview

Phase 18 upgrades AihaX from an authorized assessment engine into an evidence-first vulnerability verification and HackerOne-ready reporting system. The objective is to produce solely verified, security-impact-demonstrated findings while deterministically rejecting false positives, enforcing cryptographic SHA-256 evidence integrity, guaranteeing report count invariance, and strictly separating confirmed facts from security inferences.

---

## Key Architecture Upgrades

### 1. Transport Security Verification Strategy (`TransportSecurityVerificationStrategy`)
- **Check IDs**: `C001_Open_Port_80`, `C065_Unencrypted_Transmission`, `Insecure Transport`.
- **HTTP -> HTTPS Redirect Policy**: Normal HTTP to HTTPS `301`, `302`, `307`, `308` redirects with no plaintext credentials or sensitive data are deterministically classified as `FALSE_POSITIVE` (`REJECTED`) with exact reason:
  `"HTTP endpoint correctly redirects to HTTPS; no insecure transport impact demonstrated."`
- **Impact Verification**: Unencrypted HTTP (`status 200`) is only verified when sensitive data exposure is proven (e.g. database credentials, API keys, private tokens) or cleartext redirects leak authentication cookies.

### 2. CORS Verification Hardening (`CorsMisconfigurationStrategy`)
- **Check IDs**: `C004_CORS_Misconfiguration`, `cors_misconfiguration`.
- **Permissive Wildcard Policy**: `Access-Control-Allow-Origin: *` without credentials or sensitive data exposure is rejected with exact reason:
  `"Permissive CORS policy observed, but security-sensitive cross-origin data access was not demonstrated."`
- **Credentialed Cross-Origin Policy**: Verified only when arbitrary Origin is reflected with `Access-Control-Allow-Credentials: true` AND sensitive authenticated data is readable across origins.
- **Contradictory Evidence Handling**: If the server rejects or omits `Access-Control-Allow-Origin` for untrusted origins, it is immediately rejected as a False Positive.

### 3. Finding Lifecycle State Machine & Immutability
- **Lifecycle States**:
  - `DISCOVERED`: Initial detection.
  - `CANDIDATE`: Candidate finding queued for verification.
  - `VERIFYING`: Currently undergoing active verification.
  - `VERIFIED`: Deterministically reproduced and impact-proven.
  - `REJECTED`: Proven to be a False Positive or safe condition.
  - `INCONCLUSIVE`: Insufficient evidence or unavailable target.
  - `DUPLICATE`: Redundant finding fingerprint across scans/payloads.
  - `REPORTABLE`: Passed ReportGuard validation.
- **Transitions**: Verified immutable — invalid transitions (such as `VERIFIED -> CANDIDATE` or `REJECTED -> VERIFIED`) raise `ValueError`.

### 4. Cryptographic Evidence Hashing & Structured Impact Records
- **Evidence Hashes (`evidence_hashes`)**:
  - `proof_request_sha256`: SHA-256 hash of the exact HTTP request proof.
  - `proof_response_sha256`: SHA-256 hash of the exact HTTP response proof.
  - `payload_sha256`: SHA-256 hash of the attack vector / payload.
- **Impact Records (`impact_record`)**:
  - Structured CVSS 3.1 exploitability and impact metrics (`HIGH`, `CRITICAL`, `NONE`).
  - Confirmed vs. potential impact analysis.
  - `verifier_version`: `"1.0.0-phase18"`.
  - `confidence`: `ConfidenceLevel.CONFIRMED` (`100%`).

### 5. Report Generator Count Invariant
- **Strict Filtering**: `generate_scan_report` queries strictly `Finding.verdict == 'Verified'`, `Finding.false_positive == False`, `Finding.verification_status == 'VERIFIED'`.
- **Count Synchronization**:
  $$\text{Total Findings} = \text{len}(\text{Verified Findings}) = \sum \text{Severity Counts}$$
  Executive summary, severity breakdown table, and detailed finding pages are 100% synchronized. Unverified candidates, duplicates, and false positives are strictly excluded.

### 6. Zero Fabrication & HackerOne Report Structure
- **Zero Placeholder Guarantee**: The string `"Not available from collected evidence."` is permanently eliminated.
- **FACT vs. INFERENCE**:
  - **Confirmed Impact (FACT)**: Exact observed server responses, leaked parameters, and reproducible behaviors.
  - **Potential Impact (INFERENCE)**: Prefixed with `[INFERENCE]` to separate theoretical threat models from concrete proof.
