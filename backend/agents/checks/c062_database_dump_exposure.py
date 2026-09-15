"""C062 — Database Dump Exposure Check for AihaX."""

from __future__ import annotations

import re
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


class C062DatabaseDumpExposure(BaseCheck):
    contract = CheckContract(
        id="C062_Database_Dump_Exposure",
        name="Database Dump Exposure",
        category=CheckCategory.SENSITIVE_DATA,
        description="Detects publicly accessible database dumps (.sql, .dump, .sql.gz) containing schema definitions, user tables, hashed passwords, or raw database records.",
        severity=Severity.CRITICAL,
        vulnerability_type="Information Disclosure",
        cwe="CWE-530",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="Database backups and SQL dumps must never be stored in web-accessible directories",
        remediation_guidance="Remove all .sql and database dump files from web server directories and store backups in encrypted, access-restricted storage.",
        references=[
            "https://cwe.mitre.org/data/definitions/530.html",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
        ],
        verification_strategy="sensitive_file_exposure",
        required_evidence=["affected_url", "proof_response", "sql_dump_indicator"],
        destructive=False,
    )

    DUMP_FILES = [
        "/backup.sql",
        "/dump.sql",
        "/db.sql",
        "/database.sql",
        "/data.dump",
        "/users.sql",
    ]

    SQL_PATTERNS = re.compile(r"CREATE\s+TABLE\s+[`\"'\w]+|INSERT\s+INTO\s+[`\"'\w]+|ENGINE=InnoDB|MySQL dump|pg_dump", re.I)

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        base = target_url.rstrip("/")
        for path in self.DUMP_FILES:
            dump_url = urljoin(base + "/", path.lstrip("/"))
            spec = RequestSpec(
                url=dump_url,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            resp = await request_engine.execute(spec)
            if not resp.success or resp.response_status != 200:
                continue

            body = resp.response_body or ""
            match = self.SQL_PATTERNS.search(body)
            if match:
                snippet = body[max(0, match.start() - 10) : min(len(body), match.end() + 70)].replace("\n", " ")
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=dump_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.CRITICAL,
                    candidate_reason=f"Exposed database SQL dump file discovered at '{dump_url}'.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"dump_url": dump_url, "snippet": snippet},
                    payload=None,
                    proof_response=f"Exposed SQL Dump DDL: {snippet}",
                    confidence=95,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C062DatabaseDumpExposure)
