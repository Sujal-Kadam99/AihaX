"""C003 — Sensitive Files Exposure Check for AihaX."""

from __future__ import annotations

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


class C003SensitiveFilesExposure(BaseCheck):
    contract = CheckContract(
        id="C003_Sensitive_Files_Exposure",
        name="Sensitive Files Exposure",
        category=CheckCategory.RECON,
        description="Detects public exposure of sensitive configuration files, environment variables, or revision control metadata.",
        severity=Severity.HIGH,
        vulnerability_type="Information Disclosure",
        cwe="CWE-200",
        owasp_category="A01:2021-Broken Access Control",
        security_property="Configuration and environment files containing sensitive secrets must not be accessible",
        remediation_guidance="Block web server access to dotfiles, configuration files, and backups, and remove sensitive files from web root.",
        references=["https://cwe.mitre.org/data/definitions/200.html"],
        verification_strategy="sensitive_file_exposure",
        required_evidence=["affected_url", "proof_response", "sensitive_keyword"],
        destructive=False,
    )

    SENSITIVE_TARGETS = [
        ("/.env", ["DB_", "SECRET", "PASSWORD", "API_KEY", "APP_KEY", "AWS_"]),
        ("/.git/config", ["[core]", "[remote", "repositoryformatversion"]),
        ("/backup.zip", ["PK\x03\x04", "backup"]),
        ("/.htaccess", ["RewriteEngine", "Deny from", "AuthType"]),
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        base = target_url.rstrip("/")

        for path, keywords in self.SENSITIVE_TARGETS:
            test_url = f"{base}{path}"
            spec = RequestSpec(
                url=test_url,
                method="GET",
                follow_redirects=False,
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )

            resp_evidence = await request_engine.execute(spec)
            if not resp_evidence.success:
                continue

            # Candidate condition: 200 OK + body matches sensitive markers (not a custom 404 HTML page)
            if resp_evidence.response_status == 200 and resp_evidence.response_body:
                body = resp_evidence.response_body
                matched_kw = next((kw for kw in keywords if kw in body), None)
                if matched_kw:
                    # Found candidate sensitive file
                    snippet = body[:300].replace("\r", " ").replace("\n", " ")
                    return CheckResult(
                        check_id=self.contract.id,
                        title=self.contract.name,
                        target=test_url,
                        affected_url=test_url,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=self.contract.severity,
                        candidate_reason=f"Public HTTP 200 access to '{path}' revealed sensitive token marker '{matched_kw}'.",
                        request_ids=[resp_evidence.request_id],
                        evidence_ids=[resp_evidence.evidence_id],
                        observed_data={
                            "path": path,
                            "matched_keyword": matched_kw,
                            "status_code": resp_evidence.response_status,
                            "content_type": resp_evidence.response_headers.get("content-type"),
                            "snippet": snippet,
                        },
                        payload=path,
                        proof_response=f"HTTP/1.1 200 OK\r\n\r\n{snippet}",
                        confidence=85,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C003SensitiveFilesExposure)
