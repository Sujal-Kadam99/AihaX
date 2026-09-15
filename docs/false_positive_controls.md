# AihaX False Positive Controls & Anti-Inflation Mechanisms
## Automated Safeguards Against Exaggerated Bug Bounty Submissions

---

## 1. Problem Statement

Automated security tools frequently present minor configuration omissions as critical vulnerabilities:
1. Labeling missing HSTS as "Site Vulnerable to SSL Stripping / Man-in-the-Middle".
2. Labeling 5 successive login attempts without HTTP 429 as "Critical Missing Rate Limiting / Credential Stuffing".
3. Labeling directory indexing of `/images/` as "Information Disclosure of Sensitive Files".
4. Reporting 5 separate high/medium findings for missing security headers on the same endpoint.

Such findings waste security team triage time and harm bug bounty program credibility.

---

## 2. Hardened Verification Strategies

### 1. Missing Security Headers (`HttpResponsePropertyStrategy`)
- **Status:** `HARDENING_ONLY`.
- **Reason Code:** `HARDENING_OBSERVED`.
- **Exploitability:** `NONE` ($C_{exp} = 0.0$).
- **Contradiction Check:** If the required header is present in the response headers, status is immediately set to `FALSE_POSITIVE` (`HEADER_PRESENT_CONTRADICTION`).

### 2. Authentication Rate Limiting (`AuthRateLimitVerificationStrategy`)
- **Status:** `INCONCLUSIVE` unless bypass is demonstrated.
- **Reason Code:** `RATE_LIMIT_INSUFFICIENT_EVIDENCE`.
- **Confidence:** Bounded at 25%.
- **Bypass Check:** Only if proof response demonstrates automated stuffing success, lockout bypass, or account takeover does status elevate to `VALIDATED` (`RATE_LIMIT_BYPASS_PROVEN`).
- **Contradiction Check:** If HTTP 429 is received or `Retry-After` header is present, status is immediately set to `FALSE_POSITIVE` (`CONTROL_ENFORCED`).

### 3. Directory Listing (`DirectoryListingStrategy`)
- **Content Inspection:** Parses HTML response body.
- **Benign Assets:** If directory contains only static files (`.png`, `.jpg`, `.css`, `.js`, font assets), disposition is `HARDENING_ONLY` (`DIRECTORY_LISTING_BENIGN`), $C_{exp} = 0.0$.
- **Sensitive Assets:** If directory contains sensitive artifacts (`.env`, `.git`, `.sql`, `.bak`, `.zip`, credentials, private keys), disposition is `VALIDATED` (`DIRECTORY_LISTING_SENSITIVE`).
- **Contradiction Check:** If page does not contain directory indexing indicators (e.g. returns 403 Forbidden or custom index page), status is `FALSE_POSITIVE` (`CONTRADICTORY_EVIDENCE`).

### 4. Cleartext HTTP Redirects (`C001_Open_Port_80`)
- If port 80 responds with HTTP 301/302 redirecting to `https://`, status is `FALSE_POSITIVE` (`TRANSPORT_REDIRECT_SAFE`).

---

## 3. Correlation & Deduplication

Overlapping header findings on the same endpoint are correlated under a single parent finding:
- Parent: `C002_Missing_Security_Headers`
- Children: `C010` (HSTS), `C047` (CSP), `C049` (Clickjacking), `C050` (MIME Sniffing)
- The children reference the parent via `parent_finding_id`.
- The executive summary counts 1 consolidated hardening finding, preventing inflated counts.
