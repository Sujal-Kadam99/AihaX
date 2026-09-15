# Phase 18: HackerOne-Ready Bug Bounty Reporting Specification

## Standards and Submission Requirements

AihaX produces submission-ready vulnerability reports designed for direct ingestion into bug bounty platforms such as HackerOne and Bugcrowd, as well as internal security triage teams.

---

## Zero-Fabrication Guarantees

1. **No Hallucinated Proof**: Every finding report contains exact raw HTTP requests and responses recorded by the `EvidenceVault` and SHA-256 hashed at verification time.
2. **No Placeholder Text**: Placeholders (such as `"Not available from collected evidence."`) are strictly prohibited and structurally rejected by `ReportGuard`.
3. **Fact vs. Inference Strict Boundary**:
   - **`impact_confirmed`**: Contains concrete, empirically demonstrated security behaviors observed directly on the target (e.g., returned status codes, leaked database errors, exposed account tokens).
   - **`impact_potential`**: Contains threat model inferences explicitly labeled with `[INFERENCE]` tags to ensure triage analysts know which risks are demonstrated and which are contextual potentials.

---

## Report Data Transfer Object (DTO) Structure

```json
{
  "finding_id": "f-104928-c004",
  "title": "Credentialed Cross-Origin Resource Sharing (CORS) Misconfiguration",
  "vuln_type": "C004_CORS_Misconfiguration",
  "cwe_id": "CWE-942",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
  "cvss_score": 7.5,
  "severity": "high",
  "confidence": 95,
  "verdict": "Verified",
  "affected_url": "https://target.local/api/user/profile",
  "affected_param": "Origin",
  "proof_of_concept": {
    "request": "GET /api/user/profile HTTP/1.1\r\nHost: target.local\r\nOrigin: https://evil.com\r\nCookie: session=xyz",
    "response": "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://evil.com\r\nAccess-Control-Allow-Credentials: true\r\n\r\n{\"email\": \"admin@target.local\", \"api_key\": \"sec_123\"}",
    "payload": "Origin: https://evil.com",
    "reproduction_curl": "curl -s -i -H 'Origin: https://evil.com' -b 'session=xyz' 'https://target.local/api/user/profile'"
  },
  "impact_confirmed": "Observed server behavior demonstrates that Origin https://evil.com is reflected with Access-Control-Allow-Credentials: true, exposing authenticated user profiles.",
  "impact_potential": "[INFERENCE] An attacker hosting malicious JavaScript on evil.com could read sensitive API keys of logged-in users who visit the attacker page.",
  "steps_to_reproduce": [
    "1. Send an HTTP GET request to https://target.local/api/user/profile with header 'Origin: https://evil.com'.",
    "2. Observe response containing 'Access-Control-Allow-Origin: https://evil.com' and 'Access-Control-Allow-Credentials: true'.",
    "3. Confirm that sensitive user profile data is returned in the response body."
  ],
  "remediation": "Do not reflect arbitrary Origin headers with Access-Control-Allow-Credentials: true. Implement a strict whitelist of trusted partner origins.",
  "evidence_hashes": {
    "proof_request_sha256": "3a7b...",
    "proof_response_sha256": "9f1c...",
    "payload_sha256": "4b2e..."
  },
  "verifier_version": "1.0.0-phase18"
}
```

---

## Report Generation Modes & Invariants

1. **Full Technical Report (`mode="full"`)**: Contains complete executive summary, metrics, verification hashes, and full reproduction packages.
2. **Executive Summary (`mode="executive"`)**: High-level risk score, executive summary, verified vulnerability count, and severity breakdown table.
3. **Bug Bounty Platform Export (`mode="bugbounty"`)**: Formatted for copy-paste submission directly to HackerOne/Bugcrowd markdown editors.

### Count Invariant
Across all modes and summary charts:
$$\text{Report Total Findings} = \text{Verified Finding Count}$$
Candidate, duplicate, and false positive findings are 100% excluded.
