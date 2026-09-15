# AihaX — Automated Finding Verification Engine

## Verification Pipeline
`AutomatedFindingVerifier` operates deterministically on stored evidence:
1. **Target & Check Correlation**: Maps vulnerability class to defensible CWEs (e.g. C047 -> CWE-693, C022 -> CWE-307, C068 -> CWE-639).
2. **Evidence Completeness**: Checks presence of proof response and evidence tokens. Findings without evidence terminate as `INCONCLUSIVE`.
3. **False Positive Elimination**: Rejects contradictory findings (e.g. 301 redirects, present headers, 401/403 denials).
4. **Vulnerability Strategy Dispatch**:
   - `C001 (Cleartext HTTP)`: Redirect to HTTPS -> `FALSE_POSITIVE`, otherwise `HARDENING_ONLY`.
   - `C002/C010/C047/C049/C050 (Headers)`: Terminates as `HARDENING_ONLY` (impact=0.0).
   - `C022 (Rate Limiting)`: 5 attempts with 200/401 without bypass proof -> `INCONCLUSIVE`.
   - `C006 (Directory Listing)`: Benign files -> `HARDENING_ONLY`, sensitive credentials -> `VALIDATED`.
   - `C067/C068/C069 (IDOR/BOLA)`: Requires dual-identity differential proof.
5. **Machine Explanation**: Generates JSON justification with unmet requirements and checklist.
