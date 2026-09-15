"""C008 — Subdomain Takeover / Dangling DNS Check for AihaX."""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urlparse

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C008SubdomainTakeover(BaseCheck):
    contract = CheckContract(
        id="C008_Subdomain_Takeover",
        name="Subdomain Takeover / Dangling DNS",
        category=CheckCategory.RECON,
        description="Detects dangling DNS records (CNAME) pointing to unclaimed third-party cloud services (GitHub Pages, AWS S3, Heroku, Azure, Fastly).",
        severity=Severity.HIGH,
        vulnerability_type="Subdomain Takeover",
        cwe="CWE-404",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="DNS records must not point to unclaimed or deprovisioned cloud service providers",
        remediation_guidance="Remove the dangling DNS CNAME record or claim the matching resource name with the third-party provider.",
        references=[
            "https://cwe.mitre.org/data/definitions/404.html",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
        ],
        verification_strategy="subdomain_takeover",
        required_evidence=["affected_url", "proof_response", "service_fingerprint"],
        destructive=False,
    )

    SERVICE_FINGERPRINTS = [
        ("GitHub Pages", "There isn't a GitHub Pages site here", "github.io"),
        ("AWS S3", "NoSuchBucket", "s3.amazonaws.com"),
        ("AWS S3", "The specified bucket does not exist", "s3-website"),
        ("Heroku", "No such app", "herokuapp.com"),
        ("Heroku", "There's nothing here, yet.", "herokudns.com"),
        ("Azure", "404 Web Site not found", "azurewebsites.net"),
        ("Fastly", "Fastly error: unknown domain", "fastly.net"),
        ("Shopify", "Sorry, this shop is currently unavailable", "myshopify.com"),
        ("Bitbucket", "Repository not found", "bitbucket.io"),
        ("Ghost", "The thing you were looking for is gone", "ghost.io"),
        ("Surge.sh", "project not found", "surge.sh"),
        ("Wordpress", "Do you want to register", "wordpress.com"),
        ("Zendesk", "Help Center Closed", "zendesk.com"),
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
            follow_redirects=True,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        resp_evidence = await request_engine.execute(spec)
        if not resp_evidence.success:
            return None

        body = resp_evidence.response_body or ""
        status = resp_evidence.response_status

        # Check for signature dangling provider error bodies (typically 404 or specific error page)
        for service_name, fingerprint, cname_hint in self.SERVICE_FINGERPRINTS:
            if fingerprint.lower() in body.lower():
                return CheckResult(
                    check_id=self.contract.id,
                    title=f"{self.contract.name} ({service_name})",
                    target=target_url,
                    affected_url=target_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.HIGH,
                    candidate_reason=f"Target returned dangling cloud service fingerprint for {service_name}: '{fingerprint}' (HTTP {status}).",
                    request_ids=[resp_evidence.request_id],
                    evidence_ids=[resp_evidence.evidence_id],
                    observed_data={
                        "service_name": service_name,
                        "fingerprint": fingerprint,
                        "cname_hint": cname_hint,
                        "status": status,
                    },
                    payload=None,
                    proof_response=f"HTTP {status} - Fingerprint: {fingerprint}",
                    confidence=85,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C008SubdomainTakeover)
