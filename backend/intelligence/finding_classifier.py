"""AihaX Phase 7 — Finding Classifier.

Normalizes verified findings into deterministic vulnerability categories
based solely on existing check_id, category, and evidence fields.

Invariants:
- Never invents categories not supported by evidence.
- Always preserves original check_id (C001–C077).
- All outputs are deterministic given the same input.
- No LLM involvement in classification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Optional, Set

from backend.models.database import Finding


# ──────────────────────────────────────────────────────────────────────────────
# 1. NORMALIZED VULNERABILITY CATEGORIES
# ──────────────────────────────────────────────────────────────────────────────

VULN_CATEGORY_MAP: Dict[str, str] = {
    # Recon / Discovery
    "recon": "Reconnaissance & Information Disclosure",
    "misconfiguration": "Security Misconfiguration",
    "misconfig": "Security Misconfiguration",
    # Authentication
    "auth": "Authentication & Session Management",
    "authentication": "Authentication & Session Management",
    "session": "Authentication & Session Management",
    # Injection
    "injection": "Injection Attacks",
    "sql": "SQL Injection",
    "nosql": "NoSQL Injection",
    "command": "Command Injection",
    "ldap": "LDAP Injection",
    "el_injection": "Expression Language Injection",
    "ssti": "Server-Side Template Injection",
    # XSS
    "xss": "Cross-Site Scripting",
    # Sensitive Data
    "sensitive_data": "Sensitive Data Exposure",
    "sensitive_files": "Sensitive Files Exposure",
    # Business Logic
    "business_logic": "Business Logic Vulnerability",
    "idor": "Insecure Direct Object Reference",
    "access_control": "Broken Access Control",
    "ssrf": "Server-Side Request Forgery",
    "path_traversal": "Path Traversal",
    "lfi": "Local File Inclusion",
    "xxe": "XML External Entity Injection",
    # Transport
    "transport": "Insecure Transport",
    "tls": "TLS/SSL Misconfiguration",
    # CSP / Headers
    "headers": "Missing Security Headers",
    "csp": "Content Security Policy",
    "clickjacking": "Clickjacking",
    # Upload
    "upload": "Dangerous File Upload",
    # CORS
    "cors": "CORS Misconfiguration",
    # Other
    "race_condition": "Race Condition",
    "replay_attack": "Replay Attack",
    "subdomain_takeover": "Subdomain Takeover",
}

# Attack surface categories
ATTACK_SURFACE_MAP: Dict[str, str] = {
    "C001": "network",
    "C002": "http_headers",
    "C003": "file_system",
    "C004": "cors",
    "C005": "graphql",
    "C006": "directory",
    "C007": "redirect",
    "C008": "dns",
    "C009": "admin_interface",
    "C010": "tls",
    "C011": "technology_stack",
    "C012": "authentication",
    "C013": "session",
    "C014": "cookie",
    "C015": "cookie",
    "C016": "cookie",
    "C017": "session",
    "C018": "session",
    "C019": "password",
    "C020": "jwt",
    "C021": "jwt",
    "C022": "rate_limiting",
    "C023": "query_parameter",
    "C024": "query_parameter",
    "C025": "query_parameter",
    "C026": "query_parameter",
    "C027": "query_parameter",
    "C028": "template_engine",
    "C029": "http_headers",
    "C030": "http_headers",
    "C031": "file_system",
    "C032": "file_system",
    "C033": "xml_parser",
    "C034": "ldap",
    "C035": "el_engine",
    "C036": "server_side_request",
    "C037": "reflected_output",
    "C038": "stored_output",
    "C039": "dom",
    "C040": "html_context",
    "C041": "attribute_context",
    "C042": "javascript_context",
    "C043": "url_context",
    "C044": "dom_mutation",
    "C045": "xss_filter",
    "C046": "html_rendering",
    "C047": "csp",
    "C048": "csp",
    "C049": "framing",
    "C050": "mime",
    "C051": "cross_domain_policy",
    "C052": "http_methods",
    "C053": "default_setup",
    "C054": "error_disclosure",
    "C055": "file_upload",
    "C056": "path_normalization",
    "C057": "api_keys",
    "C058": "source_maps",
    "C059": "url_params",
    "C060": "html_comments",
    "C061": "backup_files",
    "C062": "database_dump",
    "C063": "cloud_storage",
    "C064": "vcs_metadata",
    "C065": "transport",
    "C066": "cleartext_storage",
    "C067": "object_reference",
    "C068": "object_reference",
    "C069": "api_authorization",
    "C070": "mass_assignment",
    "C071": "privilege",
    "C072": "access_control",
    "C073": "parameter",
    "C074": "workflow",
    "C075": "concurrency",
    "C076": "replay",
    "C077": "reauthentication",
}


# ──────────────────────────────────────────────────────────────────────────────
# 2. FINDING CLASSIFICATION OUTPUT
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class FindingClassification:
    """Normalized vulnerability classification for a finding."""
    check_id: str                          # Original C001–C077 ID — always preserved
    check_number: str                      # e.g., "C023"
    vulnerability_category: str           # Normalized category string
    subcategory: str                       # More specific subcategory
    attack_surface: str                    # Network surface where the vuln exists
    affected_component: str               # Specific component (e.g., "session cookie", "JWT header")
    parameter_location: str               # Where the injection point is (query, body, header, path)
    authentication_context: str           # "anonymous", "authenticated", "cross-user"
    workflow_context: str                 # "stateless", "multi-step", "workflow"
    browser_context: str                  # "none", "dom", "browser"
    owasp_top10: str                      # Primary OWASP category
    cwe: Optional[str] = None             # Inherited from check contract
    requires_auth_proof: bool = False     # True if finding needs auth context to be meaningful
    normalized_family: str = ""           # Broad vulnerability family

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "check_number": self.check_number,
            "vulnerability_category": self.vulnerability_category,
            "subcategory": self.subcategory,
            "attack_surface": self.attack_surface,
            "affected_component": self.affected_component,
            "parameter_location": self.parameter_location,
            "authentication_context": self.authentication_context,
            "workflow_context": self.workflow_context,
            "browser_context": self.browser_context,
            "owasp_top10": self.owasp_top10,
            "cwe": self.cwe,
            "requires_auth_proof": self.requires_auth_proof,
            "normalized_family": self.normalized_family,
        }


# ──────────────────────────────────────────────────────────────────────────────
# 3. FINDING CLASSIFIER
# ──────────────────────────────────────────────────────────────────────────────

class FindingClassifier:
    """Normalizes vulnerability findings into deterministic categories.

    All classification is deterministic from existing fields.
    No LLM involvement. No invented categories.
    """

    # OWASP Top 10 2021 mapping by check number range / category
    _OWASP_MAP: Dict[str, str] = {
        "A01": "A01:2021-Broken Access Control",
        "A02": "A02:2021-Cryptographic Failures",
        "A03": "A03:2021-Injection",
        "A04": "A04:2021-Insecure Design",
        "A05": "A05:2021-Security Misconfiguration",
        "A06": "A06:2021-Vulnerable and Outdated Components",
        "A07": "A07:2021-Identification and Authentication Failures",
        "A08": "A08:2021-Software and Data Integrity Failures",
        "A09": "A09:2021-Security Logging and Monitoring Failures",
        "A10": "A10:2021-Server-Side Request Forgery",
    }

    # Maps check number prefix to OWASP category
    _CHECK_OWASP: Dict[str, str] = {
        "C001": "A05", "C002": "A05", "C003": "A05", "C004": "A05",
        "C005": "A05", "C006": "A05", "C007": "A01", "C008": "A05",
        "C009": "A01", "C010": "A02", "C011": "A05", "C012": "A07",
        "C013": "A07", "C014": "A07", "C015": "A07", "C016": "A07",
        "C017": "A07", "C018": "A07", "C019": "A07", "C020": "A07",
        "C021": "A07", "C022": "A07", "C023": "A03", "C024": "A03",
        "C025": "A03", "C026": "A03", "C027": "A03", "C028": "A03",
        "C029": "A03", "C030": "A03", "C031": "A01", "C032": "A01",
        "C033": "A03", "C034": "A03", "C035": "A03", "C036": "A10",
        "C037": "A03", "C038": "A03", "C039": "A03", "C040": "A03",
        "C041": "A03", "C042": "A03", "C043": "A03", "C044": "A03",
        "C045": "A03", "C046": "A03", "C047": "A05", "C048": "A05",
        "C049": "A05", "C050": "A05", "C051": "A05", "C052": "A05",
        "C053": "A05", "C054": "A05", "C055": "A05", "C056": "A01",
        "C057": "A02", "C058": "A05", "C059": "A02", "C060": "A05",
        "C061": "A05", "C062": "A02", "C063": "A05", "C064": "A05",
        "C065": "A02", "C066": "A02", "C067": "A01", "C068": "A01",
        "C069": "A01", "C070": "A04", "C071": "A01", "C072": "A01",
        "C073": "A01", "C074": "A04", "C075": "A04", "C076": "A07",
        "C077": "A07",
    }

    # Vulnerability families by check prefix
    _VULN_FAMILY: Dict[str, str] = {
        "C001": "information_gathering",
        "C002": "misconfiguration",
        "C003": "sensitive_data_exposure",
        "C004": "cors",
        "C005": "information_gathering",
        "C006": "misconfiguration",
        "C007": "redirect",
        "C008": "subdomain",
        "C009": "misconfiguration",
        "C010": "cryptographic_failure",
        "C011": "information_gathering",
        "C012": "authentication",
        "C013": "session_management",
        "C014": "session_management",
        "C015": "session_management",
        "C016": "session_management",
        "C017": "session_management",
        "C018": "session_management",
        "C019": "authentication",
        "C020": "authentication",
        "C021": "authentication",
        "C022": "authentication",
        "C023": "injection",
        "C024": "injection",
        "C025": "injection",
        "C026": "injection",
        "C027": "injection",
        "C028": "injection",
        "C029": "injection",
        "C030": "injection",
        "C031": "path_traversal",
        "C032": "file_inclusion",
        "C033": "xxe",
        "C034": "injection",
        "C035": "injection",
        "C036": "ssrf",
        "C037": "xss",
        "C038": "xss",
        "C039": "xss",
        "C040": "xss",
        "C041": "xss",
        "C042": "xss",
        "C043": "xss",
        "C044": "xss",
        "C045": "xss",
        "C046": "xss",
        "C047": "misconfiguration",
        "C048": "misconfiguration",
        "C049": "clickjacking",
        "C050": "misconfiguration",
        "C051": "misconfiguration",
        "C052": "misconfiguration",
        "C053": "misconfiguration",
        "C054": "information_gathering",
        "C055": "file_upload",
        "C056": "path_traversal",
        "C057": "sensitive_data_exposure",
        "C058": "information_gathering",
        "C059": "sensitive_data_exposure",
        "C060": "information_gathering",
        "C061": "sensitive_data_exposure",
        "C062": "sensitive_data_exposure",
        "C063": "cloud_misconfiguration",
        "C064": "sensitive_data_exposure",
        "C065": "cryptographic_failure",
        "C066": "sensitive_data_exposure",
        "C067": "access_control",
        "C068": "access_control",
        "C069": "access_control",
        "C070": "access_control",
        "C071": "access_control",
        "C072": "access_control",
        "C073": "access_control",
        "C074": "business_logic",
        "C075": "race_condition",
        "C076": "replay_attack",
        "C077": "authentication",
    }

    @classmethod
    def classify(cls, finding: Finding) -> FindingClassification:
        """Classify a finding into normalized vulnerability categories.

        Entirely deterministic. No LLM.
        """
        check_id = str(finding.vuln_type or "")
        # Extract check number prefix (e.g., "C023" from "C023_SQL_Injection")
        m = re.match(r"^(C\d{3})", check_id)
        check_prefix = m.group(1) if m else check_id[:4]

        # Normalize category from existing data
        raw_category = str(finding.category or "").lower().strip()
        normalized_category = VULN_CATEGORY_MAP.get(raw_category, raw_category.replace("_", " ").title())

        # Attack surface
        attack_surface = ATTACK_SURFACE_MAP.get(check_prefix, "web_application")

        # Parameter location from affected_param
        param_loc = cls._classify_param_location(finding.affected_param)

        # Authentication context from verdict/evidence
        auth_ctx = cls._classify_auth_context(finding)

        # Workflow/browser context
        workflow_ctx = cls._classify_workflow_context(check_prefix)
        browser_ctx = cls._classify_browser_context(check_prefix)

        # OWASP category
        owasp_code = cls._CHECK_OWASP.get(check_prefix, "A05")
        owasp = cls._OWASP_MAP.get(owasp_code, "A05:2021-Security Misconfiguration")

        # Affected component
        affected_component = cls._infer_affected_component(finding, check_prefix)

        # Subcategory from check_id name part
        subcategory = cls._extract_subcategory(check_id)

        # Normalized family
        family = cls._VULN_FAMILY.get(check_prefix, raw_category)

        # CWE from finding model
        cwe = finding.cwe_id

        requires_auth_proof = check_prefix in {
            "C067", "C068", "C069", "C070", "C071", "C072", "C073",
            "C077", "C012", "C017", "C018",
        }

        return FindingClassification(
            check_id=check_id,
            check_number=check_prefix,
            vulnerability_category=normalized_category,
            subcategory=subcategory,
            attack_surface=attack_surface,
            affected_component=affected_component,
            parameter_location=param_loc,
            authentication_context=auth_ctx,
            workflow_context=workflow_ctx,
            browser_context=browser_ctx,
            owasp_top10=owasp,
            cwe=cwe,
            requires_auth_proof=requires_auth_proof,
            normalized_family=family,
        )

    @staticmethod
    def _classify_param_location(affected_param: Optional[str]) -> str:
        if not affected_param:
            return "unspecified"
        p = str(affected_param).lower()
        if p.startswith("header:") or ":" in p:
            return "http_header"
        if p in ("url", "path", "uri"):
            return "url_path"
        if p.startswith("cookie"):
            return "cookie"
        if p.startswith("body") or p.startswith("json") or p.startswith("form"):
            return "request_body"
        return "query_parameter"

    @staticmethod
    def _classify_auth_context(finding: Finding) -> str:
        reason = str(finding.verification_reason_code or "").upper()
        if "AUTH_REQUIRED" in reason:
            return "authentication_required"
        if "CROSS" in reason or "IDOR" in str(finding.vuln_type or "").upper():
            return "cross-user"
        return "anonymous"

    @staticmethod
    def _classify_workflow_context(check_prefix: str) -> str:
        workflow_checks = {"C017", "C018", "C074", "C075", "C076", "C077"}
        if check_prefix in workflow_checks:
            return "multi-step"
        return "stateless"

    @staticmethod
    def _classify_browser_context(check_prefix: str) -> str:
        browser_checks = {"C039", "C044", "C046"}
        if check_prefix in browser_checks:
            return "browser"
        dom_checks = {"C039", "C040", "C041", "C042", "C043", "C044"}
        if check_prefix in dom_checks:
            return "dom"
        return "none"

    @staticmethod
    def _infer_affected_component(finding: Finding, check_prefix: str) -> str:
        component_map = {
            "C010": "TLS certificate / cipher configuration",
            "C013": "session cookie",
            "C014": "session cookie (Secure flag)",
            "C015": "session cookie (HttpOnly flag)",
            "C016": "session cookie (SameSite attribute)",
            "C020": "JWT token algorithm",
            "C021": "JWT token claims",
            "C047": "Content-Security-Policy header",
            "C048": "Content-Security-Policy directives",
            "C049": "X-Frame-Options header",
            "C050": "X-Content-Type-Options header",
            "C064": "Git metadata (.git/)",
        }
        if check_prefix in component_map:
            return component_map[check_prefix]
        param = str(finding.affected_param or "")
        if param:
            return f"parameter '{param}'"
        url = str(finding.affected_url or "")
        if url:
            path = url.split("?")[0].rstrip("/").rsplit("/", 1)[-1]
            if path:
                return f"endpoint '{path}'"
        return "web application"

    @staticmethod
    def _extract_subcategory(check_id: str) -> str:
        # "C023_SQL_Injection" → "SQL Injection"
        parts = check_id.split("_", 1)
        if len(parts) > 1:
            return parts[1].replace("_", " ").title()
        return check_id


__all__ = ["FindingClassifier", "FindingClassification", "VULN_CATEGORY_MAP"]
