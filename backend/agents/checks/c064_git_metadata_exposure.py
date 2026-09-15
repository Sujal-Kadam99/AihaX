"""C064 — Version Control Metadata (.git) Exposure Check for AihaX."""

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


class C064GitMetadataExposure(BaseCheck):
    contract = CheckContract(
        id="C064_Git_Metadata_Exposure",
        name="Version Control Metadata (.git) Exposure",
        category=CheckCategory.SENSITIVE_DATA,
        description="Detects exposed Git repository metadata directories (/.git/HEAD, /.git/config) that allow attackers to reconstruct the entire application repository history and source code.",
        severity=Severity.HIGH,
        vulnerability_type="Information Disclosure",
        cwe="CWE-538",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="Version control repository metadata (.git, .svn, .hg) must be blocked from public web serving",
        remediation_guidance="Configure web servers to deny access to all hidden dotfiles and .git directories (e.g. location ~ /\\.git { deny all; }).",
        references=[
            "https://cwe.mitre.org/data/definitions/538.html",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_for_Web_Application_Components_Fingerprint",
        ],
        verification_strategy="sensitive_file_exposure",
        required_evidence=["affected_url", "proof_response", "git_head_content"],
        destructive=False,
    )

    VCS_FILES = [
        ("/.git/HEAD", "ref: refs/heads/"),
        ("/.git/config", "[core]"),
        ("/.svn/entries", "12"),
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        base = target_url.rstrip("/")
        for path, marker in self.VCS_FILES:
            vcs_url = urljoin(base + "/", path.lstrip("/"))
            spec = RequestSpec(
                url=vcs_url,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            resp = await request_engine.execute(spec)
            if not resp.success or resp.response_status != 200:
                continue

            body = resp.response_body or ""
            if marker in body:
                snippet = body[:100].strip()
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=vcs_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.HIGH,
                    candidate_reason=f"Version control metadata file exposed at '{vcs_url}' containing '{marker}'.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"vcs_url": vcs_url, "snippet": snippet},
                    payload=None,
                    proof_response=f"VCS Metadata Disclosed: {snippet}",
                    confidence=95,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C064GitMetadataExposure)
