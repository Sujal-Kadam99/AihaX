"""C033 — XML External Entity (XXE) Indicators Check for AihaX."""

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


class C033XXEIndicators(BaseCheck):
    contract = CheckContract(
        id="C033_XXE_Indicators",
        name="XML External Entity (XXE) Indicators",
        category=CheckCategory.INJECTION,
        description="Detects XML parser vulnerabilities where external entity expansion and inline DTD parsing are permitted, exposing applications to SSRF and local file disclosure.",
        severity=Severity.HIGH,
        vulnerability_type="XML Entity Injection",
        cwe="CWE-611",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="XML parsers must disable DTD processing and external entity resolution (disallow-doctype-decl = true)",
        remediation_guidance="Disable external DTDs and entity parsing across all XML parsers (e.g. setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)).",
        references=[
            "https://cwe.mitre.org/data/definitions/611.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "expanded_entity_canary"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        canary_str = "aihax_xxe_proof_token_8899"
        # Safe inline entity declaration without external network requests
        safe_xxe_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY testCanary "{canary_str}">
]>
<root><name>&testCanary;</name></root>"""

        spec = RequestSpec(
            url=target_url,
            method="POST",
            headers={"Content-Type": "application/xml", "Accept": "application/xml, text/xml, */*"},
            body=safe_xxe_payload,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        resp = await request_engine.execute(spec)
        if not resp.success:
            return None

        body = resp.response_body or ""
        # If the XML parser processed and reflected the custom entity value
        if canary_str in body and "testCanary" not in body:
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=Severity.HIGH,
                candidate_reason=f"XML parser expanded inline DTD entity '&testCanary;' to '{canary_str}' in HTTP response.",
                request_ids=[resp.request_id],
                evidence_ids=[resp.evidence_id],
                observed_data={"status": resp.response_status, "expanded_canary": canary_str},
                payload=safe_xxe_payload,
                proof_response=f"Entity Expanded in Response: '{canary_str}'",
                confidence=95,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C033XXEIndicators)
