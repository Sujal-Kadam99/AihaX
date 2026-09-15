"""C061 — Backup / Temporary File Exposure Check for AihaX."""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urljoin

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C061BackupFileExposure(BaseCheck):
    contract = CheckContract(
        id="C061_Backup_File_Exposure",
        name="Backup / Temporary File Exposure",
        category=CheckCategory.SENSITIVE_DATA,
        description="Detects publicly accessible backup, editor temporary, and archived source code files (.bak, .old, .swp, .backup, ~) that bypass server-side script execution engines and expose source code in plaintext.",
        severity=Severity.HIGH,
        vulnerability_type="Information Disclosure",
        cwe="CWE-530",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="Backup and temporary editor files must never reside in publicly served web directories",
        remediation_guidance="Disable automatic backup creation in public web folders and configure web servers to block requests matching .bak, .old, .swp, and ~ suffixes.",
        references=[
            "https://cwe.mitre.org/data/definitions/530.html",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
        ],
        verification_strategy="sensitive_file_exposure",
        required_evidence=["affected_url", "proof_response", "backup_file_indicator"],
        destructive=False,
    )

    BACKUP_FILES = [
        "/config.php.bak",
        "/index.php.bak",
        "/web.config.old",
        "/app.py.old",
        "/settings.py.bak",
        "/wp-config.php.bak",
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        base = target_url.rstrip("/")
        for path in self.BACKUP_FILES:
            backup_url = urljoin(base + "/", path.lstrip("/"))
            spec = RequestSpec(
                url=backup_url,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            resp = await request_engine.execute(spec)
            if not resp.success or resp.response_status != 200:
                continue

            body = resp.response_body or ""
            # Check if plaintext source code or config markers are returned
            if ("<?php" in body or "def " in body or "<configuration>" in body or "DB_PASSWORD" in body) and len(body) > 30:
                snippet = body[:150].replace("\n", " ")
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=backup_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.HIGH,
                    candidate_reason=f"Exposed backup file discovered at '{backup_url}' disclosing plaintext application source code.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"backup_url": backup_url, "snippet": snippet},
                    payload=None,
                    proof_response=f"Exposed Source Code in Backup File: {snippet}",
                    confidence=95,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C061BackupFileExposure)
