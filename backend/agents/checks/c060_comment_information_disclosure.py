"""C060 — Information Disclosure in Source Comments Check for AihaX."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C060CommentInformationDisclosure(BaseCheck):
    contract = CheckContract(
        id="C060_Comment_Information_Disclosure",
        name="Information Disclosure in Source Comments",
        category=CheckCategory.SENSITIVE_DATA,
        description="Detects developer comments left in HTML or client-side JavaScript exposing internal credentials, backend endpoints, database passwords, or internal architecture details.",
        severity=Severity.LOW,
        vulnerability_type="Information Disclosure",
        cwe="CWE-615",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="Production HTML and JavaScript files must strip developer comments and internal notes during build minification",
        remediation_guidance="Configure build toolchains (Webpack, Vite, Terser) to strip comments during production builds.",
        references=[
            "https://cwe.mitre.org/data/definitions/615.html",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "comment_snippet"],
        destructive=False,
    )

    COMMENT_PATTERNS = [
        ("Database Credentials Note", re.compile(r"(?:<!--|/\*|//)[^>]*?(?:password\s*=|pwd\s*=|db_pass\s*=)[^>]*?(?:-->|\*/|\n)", re.I)),
        ("Internal Architecture Note", re.compile(r"(?:<!--|/\*|//)[^>]*?(?:TODO:\s*remove|FIXME:\s*security|internal\s*ip:\s*10\.|internal\s*ip:\s*192\.168\.)[^>]*?(?:-->|\*/|\n)", re.I)),
        ("Admin Credential Comment", re.compile(r"(?:<!--|/\*|//)[^>]*?(?:admin:\s*\w+|login:\s*admin)[^>]*?(?:-->|\*/|\n)", re.I)),
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        spec = RequestSpec(
            url=target_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp = await request_engine.execute(spec)
        if not resp.success:
            return None

        body = resp.response_body or ""
        for desc, pat in self.COMMENT_PATTERNS:
            match = pat.search(body)
            if match:
                snippet = match.group(0).strip()[:200].replace("\n", " ")
                return CheckResult(
                    check_id=self.contract.id,
                    title=f"{self.contract.name} ({desc})",
                    target=target_url,
                    affected_url=target_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.LOW,
                    candidate_reason=f"Sensitive comment discovered in HTML/JS source: '{snippet}'.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"category": desc, "snippet": snippet},
                    payload=None,
                    proof_response=f"Comment Snippet ({desc}): {snippet}",
                    confidence=85,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C060CommentInformationDisclosure)
