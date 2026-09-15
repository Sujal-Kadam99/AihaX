"""C039 — DOM XSS Indicators Check for AihaX."""

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


class C039DOMXSSIndicators(BaseCheck):
    contract = CheckContract(
        id="C039_DOM_XSS_Indicators",
        name="DOM XSS Indicators",
        category=CheckCategory.XSS,
        description="Detects dangerous client-side DOM sinks (document.write, innerHTML, eval) that consume untrusted DOM sources (location.search, location.hash, document.referrer) without sanitization.",
        severity=Severity.MEDIUM,
        vulnerability_type="DOM-Based Cross-Site Scripting",
        cwe="CWE-79",
        owasp_category="A03:2021-Injection",
        security_property="Client-side JavaScript must sanitize DOM sources before writing to execution or HTML sinks",
        remediation_guidance="Use safe DOM properties like textContent instead of innerHTML, or sanitize sources with DOMPurify before inserting into DOM sinks.",
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "sink_source_pattern"],
        destructive=False,
    )

    DOM_SINKS = [
        re.compile(r"document\.write\s*\([^)]*(?:location\.|window\.location|document\.referrer|document\.URL)", re.I),
        re.compile(r"\.innerHTML\s*=\s*[^;]*(?:location\.|window\.location|document\.referrer|URLSearchParams)", re.I),
        re.compile(r"\.outerHTML\s*=\s*[^;]*(?:location\.|window\.location)", re.I),
        re.compile(r"eval\s*\([^)]*(?:location\.|window\.location|decodeURIComponent)", re.I),
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
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp = await request_engine.execute(spec)
        if not resp.success:
            return None

        body = resp.response_body or ""
        for sink_pat in self.DOM_SINKS:
            match = sink_pat.search(body)
            if match:
                snippet = body[max(0, match.start() - 15) : min(len(body), match.end() + 25)].strip()
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=target_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.MEDIUM,
                    candidate_reason=f"Dangerous client-side DOM sink/source flow identified in script: '{snippet}'.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"dom_pattern": snippet},
                    payload=None,
                    proof_response=f"Vulnerable DOM Source-to-Sink Flow: {snippet}",
                    confidence=85,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C039DOMXSSIndicators)
