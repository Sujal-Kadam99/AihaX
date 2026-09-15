"""C053 — Default / Installation Setup Page Exposed Check for AihaX."""

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


class C053DefaultSetupPage(BaseCheck):
    contract = CheckContract(
        id="C053_Default_Setup_Page",
        name="Default / Installation Setup Page Exposed",
        category=CheckCategory.MISCONFIG,
        description="Detects accessible default installation, setup wizards, and diagnostic info pages (phpinfo.php, /setup.php, /install.php, /server-status) that expose critical internal configurations or allow unauthenticated reconfiguration.",
        severity=Severity.HIGH,
        vulnerability_type="Security Misconfiguration",
        cwe="CWE-1188",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="Installation scripts and diagnostic pages must be removed or disabled after initial deployment",
        remediation_guidance="Delete or restrict access to all installation, setup, and diagnostic endpoints in production environments.",
        references=[
            "https://cwe.mitre.org/data/definitions/1188.html",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration",
        ],
        verification_strategy="sensitive_file_exposure",
        required_evidence=["affected_url", "proof_response", "setup_page_indicator"],
        destructive=False,
    )

    SETUP_TARGETS = [
        ("/phpinfo.php", re.compile(r"<title>phpinfo\(\)</title>|PHP Version \d+\.\d+", re.I), "PHP Info Diagnostic Page"),
        ("/setup.php", re.compile(r"setup wizard|installation wizard|database setup", re.I), "Setup Wizard"),
        ("/install.php", re.compile(r"install wizard|database configuration|welcome to the installation", re.I), "Installer Wizard"),
        ("/server-status", re.compile(r"Apache Server Status|Server Version:", re.I), "Apache Server Status Page"),
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        base = target_url.rstrip("/")
        for path, match_pat, desc in self.SETUP_TARGETS:
            setup_url = urljoin(base + "/", path.lstrip("/"))
            spec = RequestSpec(
                url=setup_url,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            resp = await request_engine.execute(spec)
            if not resp.success or resp.response_status != 200:
                continue

            body = resp.response_body or ""
            match = match_pat.search(body)
            if match:
                snippet = body[max(0, match.start() - 20) : min(len(body), match.end() + 50)].replace("\n", " ")
                return CheckResult(
                    check_id=self.contract.id,
                    title=f"{self.contract.name} ({desc})",
                    target=target_url,
                    affected_url=setup_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.HIGH,
                    candidate_reason=f"Exposed {desc} discovered publicly accessible at '{setup_url}'.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"setup_url": setup_url, "desc": desc, "snippet": snippet},
                    payload=None,
                    proof_response=f"Exposed Page Signature ({desc}): {snippet}",
                    confidence=95,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C053DefaultSetupPage)
