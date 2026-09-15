"""C058 — Source Map Exposure Check for AihaX."""

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


class C058SourceMapExposure(BaseCheck):
    contract = CheckContract(
        id="C058_Source_Map_Exposure",
        name="Source Map Exposure",
        category=CheckCategory.SENSITIVE_DATA,
        description="Detects publicly accessible JavaScript and CSS source maps (.js.map) that disclose unminified application source code, comments, internal module hierarchies, and developer endpoints.",
        severity=Severity.LOW,
        vulnerability_type="Information Disclosure",
        cwe="CWE-540",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="Source maps containing original unminified source code must not be exposed to unauthenticated public users",
        remediation_guidance="Disable production source map generation or restrict source map files to internal development networks.",
        references=[
            "https://cwe.mitre.org/data/definitions/540.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Source_Map_Security_Cheat_Sheet.html",
        ],
        verification_strategy="sensitive_file_exposure",
        required_evidence=["affected_url", "proof_response", "source_map_indicator"],
        destructive=False,
    )

    MAP_PATHS = ["/static/js/main.js.map", "/main.js.map", "/app.js.map", "/bundle.js.map", "/index.js.map"]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        base = target_url.rstrip("/")
        for path in self.MAP_PATHS:
            map_url = urljoin(base + "/", path.lstrip("/"))
            spec = RequestSpec(
                url=map_url,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            resp = await request_engine.execute(spec)
            if not resp.success or resp.response_status != 200:
                continue

            body = resp.response_body or ""
            if '"version":3' in body and '"sources":' in body:
                return CheckResult(
                    check_id=self.contract.id,
                    title=self.contract.name,
                    target=target_url,
                    affected_url=map_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.LOW,
                    candidate_reason=f"JavaScript source map exposed at '{map_url}', disclosing original unminified application source code.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"map_url": map_url, "size": len(body)},
                    payload=None,
                    proof_response=f"Source Map Content: {body[:200]}",
                    confidence=95,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C058SourceMapExposure)
