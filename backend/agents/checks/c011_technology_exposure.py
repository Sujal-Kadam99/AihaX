"""C011 — Technology / Version Exposure Check for AihaX."""

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


class C011TechnologyVersionExposure(BaseCheck):
    contract = CheckContract(
        id="C011_Technology_Exposure",
        name="Technology / Version Exposure",
        category=CheckCategory.RECON,
        description="Detects verbose technology stack and exact version disclosure in HTTP headers and HTML metadata (Server, X-Powered-By, X-AspNet-Version, generator tags).",
        severity=Severity.INFO,
        vulnerability_type="Information Disclosure",
        cwe="CWE-200",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="Web servers should suppress detailed version banners that assist attackers in vulnerability targeting",
        remediation_guidance="Disable verbose Server banners (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx) and remove X-Powered-By headers.",
        references=[
            "https://cwe.mitre.org/data/definitions/200.html",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
        ],
        verification_strategy="http_response_property",
        required_evidence=["affected_url", "proof_response", "disclosed_version"],
        destructive=False,
    )

    VERSION_PATTERN = re.compile(r"\b\d+\.\d+(?:\.\d+)?\b")

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

        resp_evidence = await request_engine.execute(spec)
        if not resp_evidence.success:
            return None

        headers = resp_evidence.response_headers
        disclosed = []

        for h_name in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime", "X-Version"]:
            for k, v in headers.items():
                if k.lower() == h_name.lower():
                    # Check if header contains a specific version number
                    if self.VERSION_PATTERN.search(v):
                        disclosed.append(f"{k}: {v}")

        # Check HTML meta generator tag
        body = resp_evidence.response_body or ""
        generator_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', body, re.IGNORECASE)
        if generator_match:
            gen_val = generator_match.group(1)
            if self.VERSION_PATTERN.search(gen_val):
                disclosed.append(f'<meta name="generator" content="{gen_val}">')

        if disclosed:
            proof = "\r\n".join(disclosed)
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=Severity.INFO,
                candidate_reason=f"Server exposes detailed version and technology fingerprints: {', '.join(disclosed)}.",
                request_ids=[resp_evidence.request_id],
                evidence_ids=[resp_evidence.evidence_id],
                observed_data={"disclosed_headers": disclosed, "status": resp_evidence.response_status},
                payload=None,
                proof_response=proof,
                confidence=95,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C011TechnologyVersionExposure)
