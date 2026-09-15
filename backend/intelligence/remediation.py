"""AihaX Phase 7 — Remediation Engine.

Generates deterministic, advisory remediation guidance based on
vulnerability category and check_id.

Invariants:
- Guidance is category-based and deterministic (same input → same output).
- No framework-specific fixes unless framework evidence exists in the finding.
- No LLM involvement.
- All guidance is advisory — the analyst must validate applicability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from backend.models.database import Finding


# ──────────────────────────────────────────────────────────────────────────────
# 1. REMEDIATION GUIDANCE
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class RemediationGuidance:
    """Deterministic remediation guidance for a verified finding."""
    check_id: str
    vulnerability_family: str
    short_fix: str                         # One-sentence summary
    detailed_steps: List[str]              # Ordered remediation steps
    defense_in_depth: List[str]            # Additional defense layers
    cwe_references: List[str]             # CWE IDs
    owasp_references: List[str]           # OWASP references
    verification_note: str = ""            # How to verify the fix was applied

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "vulnerability_family": self.vulnerability_family,
            "short_fix": self.short_fix,
            "detailed_steps": self.detailed_steps,
            "defense_in_depth": self.defense_in_depth,
            "cwe_references": self.cwe_references,
            "owasp_references": self.owasp_references,
            "verification_note": self.verification_note,
        }


# ──────────────────────────────────────────────────────────────────────────────
# 2. REMEDIATION DATABASE (static, deterministic)
# ──────────────────────────────────────────────────────────────────────────────

_REMEDIATION_DB: Dict[str, Dict[str, Any]] = {
    # ── SQL Injection (C023, C024) ────────────────────────────────────────────
    "sql_injection": {
        "short_fix": "Use parameterized queries or prepared statements for all database interactions.",
        "detailed_steps": [
            "Replace all string-concatenated SQL with parameterized queries (e.g., cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))).",
            "Apply an ORM with parameterized binding if direct SQL is required.",
            "Validate and allowlist all input data types before use in queries.",
            "Apply least-privilege database accounts — application accounts should not have DDL permissions.",
            "Enable database error suppression in production to prevent error-based information leakage.",
        ],
        "defense_in_depth": [
            "Apply WAF rules as a secondary layer (not a primary defense).",
            "Enable database query logging and alerting for anomalous queries.",
            "Conduct regular code reviews for SQL construction patterns.",
        ],
        "cwes": ["CWE-89", "CWE-564"],
        "owasp": ["A03:2021-Injection"],
        "verification_note": "Verify by sending the same payload — the query should execute without error and without unintended data exposure.",
    },

    # ── NoSQL Injection (C025) ────────────────────────────────────────────────
    "nosql_injection": {
        "short_fix": "Use typed query builders and validate that user input cannot inject query operators.",
        "detailed_steps": [
            "Reject or sanitize input containing MongoDB operators ($where, $gt, $ne, $regex).",
            "Use strongly-typed schema validation (e.g., Joi, Zod) before building queries.",
            "Prefer query builders over raw JSON query construction from user input.",
        ],
        "defense_in_depth": ["Enable query profiling.", "Monitor for unusual operator patterns."],
        "cwes": ["CWE-943"],
        "owasp": ["A03:2021-Injection"],
        "verification_note": "Confirm operator injection no longer bypasses authentication or filters.",
    },

    # ── Command Injection (C026, C027) ────────────────────────────────────────
    "command_injection": {
        "short_fix": "Eliminate shell command construction from user input entirely.",
        "detailed_steps": [
            "Replace shell-based calls with language-native APIs (e.g., use Python's subprocess with a list argument and shell=False).",
            "If shell invocation is unavoidable, use an allowlist of permitted commands and arguments.",
            "Never pass raw user input into os.system(), exec(), eval(), or subprocess(shell=True).",
            "Apply strict server-side input validation for all parameters used in command construction.",
        ],
        "defense_in_depth": [
            "Run application with minimal OS privileges (principle of least privilege).",
            "Apply OS-level sandboxing (AppArmor, seccomp) to limit system call access.",
            "Monitor for anomalous subprocess activity.",
        ],
        "cwes": ["CWE-78", "CWE-88"],
        "owasp": ["A03:2021-Injection"],
        "verification_note": "Verify that the payload no longer executes system commands.",
    },

    # ── XSS (C037–C046) ──────────────────────────────────────────────────────
    "xss": {
        "short_fix": "Apply contextual output encoding for all user-controlled data rendered in HTML.",
        "detailed_steps": [
            "HTML-encode all user-controlled data inserted into HTML context.",
            "JavaScript-encode data inserted into script contexts.",
            "URL-encode data inserted into href/src attributes.",
            "Use a Content Security Policy (CSP) header with script-src 'nonce' to reduce XSS impact.",
            "For stored XSS: validate and sanitize input at write time using an allowlist-based HTML sanitizer.",
            "Avoid innerHTML, document.write(), and eval() with untrusted data.",
        ],
        "defense_in_depth": [
            "Implement a strict CSP with report-uri.",
            "Enable X-XSS-Protection: 1; mode=block (legacy browsers).",
            "Use Subresource Integrity (SRI) for third-party scripts.",
        ],
        "cwes": ["CWE-79", "CWE-80"],
        "owasp": ["A03:2021-Injection"],
        "verification_note": "Confirm the payload is encoded/escaped in the response and does not execute in the browser.",
    },

    # ── SSTI (C028) ───────────────────────────────────────────────────────────
    "ssti": {
        "short_fix": "Never pass user-controlled input directly to template rendering functions.",
        "detailed_steps": [
            "Separate template logic from user data — use safe variable substitution, not template compilation from user input.",
            "Apply a sandboxed template environment if dynamic templates are required.",
            "Validate and allowlist template variable names against a known schema.",
        ],
        "defense_in_depth": [
            "Run template engine with minimal permissions.",
            "Monitor for arithmetic-pattern canaries in logs.",
        ],
        "cwes": ["CWE-94"],
        "owasp": ["A03:2021-Injection"],
        "verification_note": "Verify that template expressions are not evaluated from user input.",
    },

    # ── Path Traversal / LFI (C031, C032, C056) ──────────────────────────────
    "path_traversal": {
        "short_fix": "Validate and canonicalize file paths before use; reject paths containing '../' or absolute references.",
        "detailed_steps": [
            "Resolve the canonical path (os.path.realpath()) and verify it starts with the intended base directory.",
            "Use an allowlist of permitted filenames rather than accepting arbitrary paths.",
            "Do not expose internal file structure through error messages.",
        ],
        "defense_in_depth": [
            "Run web server with minimal filesystem permissions.",
            "Apply chroot or container isolation.",
        ],
        "cwes": ["CWE-22", "CWE-23"],
        "owasp": ["A01:2021-Broken Access Control"],
        "verification_note": "Confirm that traversal sequences no longer access files outside the intended directory.",
    },

    # ── SSRF (C036) ───────────────────────────────────────────────────────────
    "ssrf": {
        "short_fix": "Apply a strict allowlist of permitted destinations for all server-initiated outbound requests.",
        "detailed_steps": [
            "Validate user-supplied URLs against a destination allowlist before fetching.",
            "Block requests to private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x, 169.254.x.x).",
            "Disable HTTP redirects or re-validate the redirect destination.",
            "Use a dedicated egress proxy that enforces the allowlist at network level.",
        ],
        "defense_in_depth": [
            "Apply network-level egress controls (firewall rules).",
            "Monitor outbound request patterns for unexpected internal destinations.",
            "Block cloud metadata endpoints (169.254.169.254) at network level.",
        ],
        "cwes": ["CWE-918"],
        "owasp": ["A10:2021-Server-Side Request Forgery"],
        "verification_note": "Confirm that requests to internal/private IPs are blocked and return an error.",
    },

    # ── IDOR / BOLA (C067, C068, C069) ───────────────────────────────────────
    "idor": {
        "short_fix": "Enforce server-side object authorization — verify the requesting user owns or is authorized to access each object before returning it.",
        "detailed_steps": [
            "For every object access, verify the authenticated user's identity matches the object's owner or has an explicit access grant.",
            "Do not rely solely on obscurity (UUIDs, hashed IDs) as an access control mechanism.",
            "Use indirect object references (session-bound mappings) instead of direct database IDs.",
            "Apply unit tests that verify cross-user access is denied.",
        ],
        "defense_in_depth": [
            "Enable audit logging for all object access operations.",
            "Implement rate limiting on object access endpoints.",
        ],
        "cwes": ["CWE-639", "CWE-284"],
        "owasp": ["A01:2021-Broken Access Control"],
        "verification_note": "Confirm that User A's session cannot access User B's objects.",
    },

    # ── Mass Assignment (C070) ────────────────────────────────────────────────
    "mass_assignment": {
        "short_fix": "Use explicit field allowlists (not blocklists) when binding request body to model attributes.",
        "detailed_steps": [
            "Define an explicit schema for accepted request body fields.",
            "Ignore or reject fields not in the allowlist.",
            "Never bind raw request bodies directly to ORM models.",
        ],
        "defense_in_depth": ["Apply principle of least privilege to data fields.", "Log unexpected field submissions."],
        "cwes": ["CWE-915"],
        "owasp": ["A04:2021-Insecure Design"],
        "verification_note": "Confirm that injecting extra fields (e.g., role=admin) has no effect.",
    },

    # ── JWT Weakness (C020, C021) ─────────────────────────────────────────────
    "jwt_weakness": {
        "short_fix": "Enforce a strict algorithm allowlist and validate all JWT claims server-side.",
        "detailed_steps": [
            "Allowlist only strong algorithms (RS256, ES256). Explicitly reject 'none' and weak HMAC variants.",
            "Validate all claims: exp, iss, aud, sub on every request.",
            "Use a well-maintained JWT library — do not implement custom JWT parsing.",
            "Rotate signing keys on a schedule and maintain a key revocation mechanism.",
        ],
        "defense_in_depth": [
            "Monitor for JWTs with modified algorithms in logs.",
            "Implement token binding where supported.",
        ],
        "cwes": ["CWE-347", "CWE-327"],
        "owasp": ["A07:2021-Identification and Authentication Failures"],
        "verification_note": "Confirm 'none' algorithm JWTs and self-signed JWTs are rejected.",
    },

    # ── Session Management (C013–C018) ───────────────────────────────────────
    "session_management": {
        "short_fix": "Set Secure, HttpOnly, and SameSite attributes on all session cookies and invalidate sessions on logout.",
        "detailed_steps": [
            "Set Secure flag on all cookies containing session tokens.",
            "Set HttpOnly flag to prevent JavaScript access.",
            "Set SameSite=Strict or SameSite=Lax to mitigate CSRF.",
            "Generate a new session token after authentication (prevents session fixation).",
            "Invalidate server-side session on logout (not just clearing the client cookie).",
        ],
        "defense_in_depth": [
            "Implement session idle timeout and absolute session timeout.",
            "Bind sessions to IP or user-agent (with careful UX consideration).",
        ],
        "cwes": ["CWE-614", "CWE-384", "CWE-613"],
        "owasp": ["A07:2021-Identification and Authentication Failures"],
        "verification_note": "Confirm cookies have all three flags and old session tokens are rejected after logout.",
    },

    # ── CORS (C004) ───────────────────────────────────────────────────────────
    "cors": {
        "short_fix": "Apply a strict CORS origin allowlist; never use wildcard origins with credentials.",
        "detailed_steps": [
            "Maintain an explicit list of trusted origins.",
            "Never combine 'Access-Control-Allow-Origin: *' with 'Access-Control-Allow-Credentials: true'.",
            "Validate the Origin header server-side against the allowlist.",
            "Apply CORS headers only to API endpoints that require cross-origin access.",
        ],
        "defense_in_depth": ["Use CSRF tokens for state-changing operations.", "Audit CORS policy on each deployment."],
        "cwes": ["CWE-942"],
        "owasp": ["A05:2021-Security Misconfiguration"],
        "verification_note": "Confirm unauthorized origins receive appropriate rejection.",
    },

    # ── Missing Security Headers (C002, C047, C048, C049, C050) ──────────────
    "missing_security_headers": {
        "short_fix": "Add all required security headers to HTTP responses.",
        "detailed_steps": [
            "Add Content-Security-Policy with appropriate directives.",
            "Add X-Frame-Options: DENY or SAMEORIGIN.",
            "Add X-Content-Type-Options: nosniff.",
            "Add Strict-Transport-Security: max-age=31536000; includeSubDomains.",
            "Add Referrer-Policy: strict-origin-when-cross-origin.",
            "Add Permissions-Policy to restrict browser features.",
        ],
        "defense_in_depth": [
            "Use securityheaders.com to validate the response headers.",
            "Automate header injection at the reverse proxy level.",
        ],
        "cwes": ["CWE-693", "CWE-1021"],
        "owasp": ["A05:2021-Security Misconfiguration"],
        "verification_note": "Confirm all headers appear in production responses.",
    },

    # ── Subdomain Takeover (C008) ─────────────────────────────────────────────
    "subdomain_takeover": {
        "short_fix": "Remove or reclaim DNS records pointing to decommissioned services.",
        "detailed_steps": [
            "Audit all DNS CNAME records and verify each target service is still active and controlled.",
            "Remove CNAME records pointing to services that no longer exist.",
            "For cloud services (S3, GitHub Pages, Heroku), reclaim the subdomain before deleting the resource.",
        ],
        "defense_in_depth": [
            "Implement a DNS asset inventory process.",
            "Monitor DNS records for unexpected changes.",
        ],
        "cwes": ["CWE-350"],
        "owasp": ["A05:2021-Security Misconfiguration"],
        "verification_note": "Confirm the subdomain resolves to a controlled service or returns NXDOMAIN.",
    },

    # ── File Upload (C055) ────────────────────────────────────────────────────
    "file_upload": {
        "short_fix": "Validate uploaded file content type, extension, and size; store files outside the web root.",
        "detailed_steps": [
            "Validate the actual file content (magic bytes) — not just the Content-Type header.",
            "Apply an allowlist of permitted file extensions.",
            "Rename uploaded files to random names to prevent path-guessing.",
            "Store uploaded files outside the web root or in a separate storage bucket.",
            "Never execute uploaded files — disable execute permissions on the upload directory.",
        ],
        "defense_in_depth": [
            "Scan uploaded files with an antivirus/malware engine.",
            "Serve uploaded files via a content-delivery mechanism that sets Content-Disposition: attachment.",
        ],
        "cwes": ["CWE-434", "CWE-73"],
        "owasp": ["A05:2021-Security Misconfiguration"],
        "verification_note": "Confirm that executable payloads are rejected and non-executable files are stored safely.",
    },

    # ── Sensitive Data Exposure (C003, C057–C066) ─────────────────────────────
    "sensitive_data_exposure": {
        "short_fix": "Remove or access-control all exposed sensitive files and data.",
        "detailed_steps": [
            "Remove backup files, database dumps, .git directories, and source maps from the web root.",
            "Restrict access to configuration files and API keys via server-side access controls.",
            "Rotate any exposed credentials or API keys immediately.",
            "Apply a robots.txt and HTTP authentication to administrative paths.",
        ],
        "defense_in_depth": [
            "Run periodic automated scans for exposed sensitive files.",
            "Apply a Content-Disposition: attachment header for file downloads.",
        ],
        "cwes": ["CWE-200", "CWE-538", "CWE-312"],
        "owasp": ["A02:2021-Cryptographic Failures", "A05:2021-Security Misconfiguration"],
        "verification_note": "Confirm the exposed resource returns 403/404 after remediation.",
    },

    # ── TLS/Transport (C010, C065) ────────────────────────────────────────────
    "tls_misconfiguration": {
        "short_fix": "Upgrade to TLS 1.2+ and disable insecure cipher suites.",
        "detailed_steps": [
            "Disable TLS 1.0 and TLS 1.1.",
            "Enable only strong cipher suites (ECDHE-RSA-AES256-GCM-SHA384, etc.).",
            "Enable HSTS with a long max-age and includeSubDomains.",
            "Obtain certificates from a trusted CA with a validity period ≤ 398 days.",
        ],
        "defense_in_depth": [
            "Use SSL Labs / testssl.sh to validate configuration.",
            "Pin certificates where applicable.",
        ],
        "cwes": ["CWE-326", "CWE-295"],
        "owasp": ["A02:2021-Cryptographic Failures"],
        "verification_note": "Confirm TLS 1.3 is negotiated and weak ciphers are rejected.",
    },

    # ── Race Condition (C075) ─────────────────────────────────────────────────
    "race_condition": {
        "short_fix": "Apply server-side idempotency controls and database-level locking for critical operations.",
        "detailed_steps": [
            "Use database transactions with appropriate isolation levels (SERIALIZABLE for critical operations).",
            "Apply idempotency keys for sensitive operations (payments, transfers).",
            "Use atomic operations (e.g., compare-and-swap) for shared state.",
            "Implement per-user rate limiting for critical endpoints.",
        ],
        "defense_in_depth": [
            "Monitor for duplicate request signatures at the API gateway.",
            "Apply distributed locking (e.g., Redis SETNX) for cross-instance operations.",
        ],
        "cwes": ["CWE-362"],
        "owasp": ["A04:2021-Insecure Design"],
        "verification_note": "Confirm concurrent requests do not produce duplicate effects.",
    },

    # ── XXE (C033) ────────────────────────────────────────────────────────────
    "xxe": {
        "short_fix": "Disable external entity processing in all XML parsers.",
        "detailed_steps": [
            "Set FEATURE_SECURE_PROCESSING and disable FEATURE_EXTERNAL_GENERAL_ENTITIES in the XML parser.",
            "For Python's lxml, use resolve_entities=False.",
            "Use JSON instead of XML where possible.",
            "Validate and allowlist XML schema before parsing.",
        ],
        "defense_in_depth": [
            "Run XML parsers in a network-isolated sandbox.",
        ],
        "cwes": ["CWE-611"],
        "owasp": ["A03:2021-Injection"],
        "verification_note": "Confirm external entity references are not resolved.",
    },

    # ── Default / fallback ────────────────────────────────────────────────────
    "generic": {
        "short_fix": "Apply the principle of least privilege and defense-in-depth for the identified vulnerability.",
        "detailed_steps": [
            "Review the affected component and apply vendor or community security guidance.",
            "Apply input validation and output encoding as appropriate.",
            "Enable logging and alerting for the affected functionality.",
        ],
        "defense_in_depth": ["Conduct a security code review.", "Apply penetration testing to validate the fix."],
        "cwes": [],
        "owasp": [],
        "verification_note": "Verify the vulnerability signal is no longer present after the fix.",
    },
}

# Map check prefixes to remediation DB keys
_CHECK_TO_FAMILY: Dict[str, str] = {
    "C023": "sql_injection", "C024": "sql_injection",
    "C025": "nosql_injection",
    "C026": "command_injection", "C027": "command_injection",
    "C028": "ssti",
    "C031": "path_traversal", "C032": "path_traversal", "C056": "path_traversal",
    "C033": "xxe",
    "C036": "ssrf",
    "C037": "xss", "C038": "xss", "C039": "xss", "C040": "xss",
    "C041": "xss", "C042": "xss", "C043": "xss", "C044": "xss",
    "C045": "xss", "C046": "xss",
    "C020": "jwt_weakness", "C021": "jwt_weakness",
    "C013": "session_management", "C014": "session_management",
    "C015": "session_management", "C016": "session_management",
    "C017": "session_management", "C018": "session_management",
    "C004": "cors",
    "C002": "missing_security_headers", "C047": "missing_security_headers",
    "C048": "missing_security_headers", "C049": "missing_security_headers",
    "C050": "missing_security_headers",
    "C008": "subdomain_takeover",
    "C055": "file_upload",
    "C003": "sensitive_data_exposure", "C057": "sensitive_data_exposure",
    "C058": "sensitive_data_exposure", "C059": "sensitive_data_exposure",
    "C060": "sensitive_data_exposure", "C061": "sensitive_data_exposure",
    "C062": "sensitive_data_exposure", "C063": "sensitive_data_exposure",
    "C064": "sensitive_data_exposure", "C066": "sensitive_data_exposure",
    "C010": "tls_misconfiguration", "C065": "tls_misconfiguration",
    "C067": "idor", "C068": "idor", "C069": "idor",
    "C070": "mass_assignment",
    "C075": "race_condition",
}


# ──────────────────────────────────────────────────────────────────────────────
# 3. REMEDIATION ENGINE
# ──────────────────────────────────────────────────────────────────────────────

class RemediationEngine:
    """Generates deterministic, category-based remediation guidance."""

    @classmethod
    def generate(cls, finding: Finding) -> RemediationGuidance:
        """Generate remediation guidance for a finding."""
        check_id = str(finding.vuln_type or "")
        m = re.match(r"^(C\d{3})", check_id)
        prefix = m.group(1) if m else ""

        family = _CHECK_TO_FAMILY.get(prefix, "generic")
        db_entry = _REMEDIATION_DB[family]

        return RemediationGuidance(
            check_id=check_id,
            vulnerability_family=family,
            short_fix=db_entry["short_fix"],
            detailed_steps=list(db_entry["detailed_steps"]),
            defense_in_depth=list(db_entry["defense_in_depth"]),
            cwe_references=list(db_entry["cwes"]),
            owasp_references=list(db_entry["owasp"]),
            verification_note=db_entry.get("verification_note", ""),
        )

    @classmethod
    def get_family(cls, check_id: str) -> str:
        """Return the vulnerability family for a given check ID."""
        m = re.match(r"^(C\d{3})", check_id)
        prefix = m.group(1) if m else ""
        return _CHECK_TO_FAMILY.get(prefix, "generic")


__all__ = ["RemediationGuidance", "RemediationEngine"]
