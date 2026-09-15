"""C051 — Cross-Domain Policy Misconfiguration Check for AihaX."""

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


class C051CrossDomainPolicy(BaseCheck):
    contract = CheckContract(
        id="C051_Cross_Domain_Policy",
        name="Cross-Domain Policy Misconfiguration",
        category=CheckCategory.MISCONFIG,
        description="Detects overly permissive cross-domain policy files (/crossdomain.xml, /clientaccesspolicy.xml) granting wildcard (*) access to Flash, Silverlight, or PDF clients.",
        severity=Severity.LOW,
        vulnerability_type="Cross-Origin Misconfiguration",
        cwe="CWE-942",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="Cross-domain policy files must not grant wildcard access to untrusted domains",
        remediation_guidance="Restrict crossdomain.xml domain origins to specific trusted domains or remove legacy policy files entirely.",
        references=[
            "https://cwe.mitre.org/data/definitions/942.html",
            "https://owasp.org/www-community/attacks/Cross-domain_policy",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "policy_content"],
        destructive=False,
    )

    POLICY_FILES = ["/crossdomain.xml", "/clientaccesspolicy.xml"]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        base = target_url.rstrip("/")
        for path in self.POLICY_FILES:
            policy_url = urljoin(base + "/", path.lstrip("/"))
            spec = RequestSpec(
                url=policy_url,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            resp = await request_engine.execute(spec)
            if not resp.success or resp.response_status != 200:
                continue

            body = resp.response_body or ""
            if ('domain="*"' in body or "domain='*'" in body or "<allow-from http-request-headers" in body) and "<" in body:
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=policy_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.LOW,
                    candidate_reason=f"Overly permissive cross-domain policy granting wildcard domain access (*) discovered at '{policy_url}'.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"policy_url": policy_url, "snippet": body[:200]},
                    payload=None,
                    proof_response=f"Wildcard Policy Discovered: {body[:150]}",
                    confidence=95,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C051CrossDomainPolicy)
