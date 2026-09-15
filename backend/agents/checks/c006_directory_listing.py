"""C006 — Directory Listing Check for AihaX."""

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


class C006DirectoryListing(BaseCheck):
    contract = CheckContract(
        id="C006_Directory_Listing",
        name="Directory Listing Enabled",
        category=CheckCategory.RECON,
        description="Detects whether directory browsing/indexing is enabled on the web server, exposing directory contents and underlying file paths.",
        severity=Severity.LOW,
        vulnerability_type="Security Misconfiguration",
        cwe="CWE-548",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="Web server must not generate directory listings for directories without default index documents",
        remediation_guidance="Disable directory browsing/indexing in server configuration (e.g. 'Options -Indexes' in Apache, 'autoindex off;' in Nginx).",
        references=["https://cwe.mitre.org/data/definitions/548.html"],
        verification_strategy="directory_listing",
        required_evidence=["affected_url", "proof_response"],
        destructive=False,
    )

    DIRECTORY_PATHS = ["/", "/images/", "/static/", "/uploads/", "/assets/"]
    DIR_INDICATORS = [
        "Index of /",
        "Directory listing for",
        "<title>Index of",
        "[To Parent Directory]",
        "Last modified</a>",
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        base = target_url.rstrip("/")

        for path in self.DIRECTORY_PATHS:
            dir_url = f"{base}{path}"
            spec = RequestSpec(
                url=dir_url,
                method="GET",
                follow_redirects=False,
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )

            resp_evidence = await request_engine.execute(spec)
            if not resp_evidence.success:
                continue

            body = resp_evidence.response_body or ""
            matched_indicator = next((ind for ind in self.DIR_INDICATORS if ind.lower() in body.lower()), None)
            if resp_evidence.response_status == 200 and matched_indicator:
                snippet = body[:300].replace("\r", " ").replace("\n", " ")
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=dir_url,
                    affected_url=dir_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=self.contract.severity,
                    candidate_reason=f"Directory path '{path}' returned HTTP 200 with directory listing marker '{matched_indicator}'.",
                    request_ids=[resp_evidence.request_id],
                    evidence_ids=[resp_evidence.evidence_id],
                    observed_data={
                        "path": path,
                        "status_code": resp_evidence.response_status,
                        "matched_indicator": matched_indicator,
                        "snippet": snippet,
                    },
                    payload=path,
                    proof_response=f"HTTP/1.1 200 OK\r\n\r\n{snippet}",
                    confidence=80,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C006DirectoryListing)
