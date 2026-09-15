# AihaX — Policy & Bug Bounty Eligibility Model

## Separation of Technical Validity from Bounty Eligibility
A condition can be technically real while remaining out-of-scope for bug bounty compensation:
1. **Standard Exclusions**:
   - Denial of Service (DoS/DDoS) -> Strictly `INELIGIBLE`.
   - Missing security headers without demonstrated exploit chain -> `INELIGIBLE`.
   - Rate limiting without credential stuffing / account takeover proof -> `INELIGIBLE`.
   - Benign directory listings (images, icons) -> `INELIGIBLE`.
   - Self-XSS, logout CSRF, SPF/DMARC -> `INELIGIBLE`.
2. **Program Policy Rules**:
   - Custom scope rules defined in Program metadata take precedence.
3. **The UNKNOWN Policy Invariant (Proof L)**:
   - When policy rules are unavailable, technical validity may be established (`VALIDATED`), but bounty eligibility defaults strictly to `UNKNOWN`. It NEVER defaults to `ELIGIBLE`.
