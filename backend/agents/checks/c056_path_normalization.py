"""C056 — Path Normalization Inconsistency Check for AihaX."""

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


class C056PathNormalization(BaseCheck):
    contract = CheckContract(
        id="C056_Path_Normalization",
        name="Path Normalization Inconsistency",
        category=CheckCategory.MISCONFIG,
        description="Detects path normalization discrepancies between reverse proxies and backend application servers caused by matrix parameters (/..;/), double encoding (%252e%252e/), or semicolon truncation.",
        severity=Severity.MEDIUM,
        vulnerability_type="Security Misconfiguration",
        cwe="CWE-436",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="Reverse proxies and application servers must normalize URL paths identically before evaluating authorization rules",
        remediation_guidance="Standardize URL decoding and normalization rules between edge reverse proxies (Nginx, HAProxy) and backend application frameworks.",
        references=[
            "https://cwe.mitre.org/data/definitions/436.html",
            "https://portswigger.net/research/breaking-parser-logic-take-your-path-normalization-off-and-pop-0days-out",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "normalization_discrepancy"],
        destructive=False,
    )

    NORMALIZATION_VARIANTS = [
        ("/admin/..;/", "Tomcat Matrix Parameter Semicolon (/..;/)"),
        ("/%2e%2e/", "URL-encoded Dot Dot (/%2e%2e/)"),
        ("/static/..%2fadmin", "Encoded Slash Traversal (..%2f)"),
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        base = target_url.rstrip("/")

        for path_suffix, desc in self.NORMALIZATION_VARIANTS:
            test_url = f"{base}{path_suffix}"
            spec = RequestSpec(
                url=test_url,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            )
            resp = await request_engine.execute(spec)
            if not resp.success:
                continue

            # If the server handles matrix or encoded traversal returning 200 without normalizing/rejecting
            if resp.response_status == 200 and len(resp.response_body or "") > 50:
                return CheckResult(
                    check_id=self.contract.id,
                    title=f"{self.contract.name} ({desc})",
                    target=target_url,
                    affected_url=test_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.MEDIUM,
                    candidate_reason=f"Path normalization discrepancy observed: URL variant '{path_suffix}' ({desc}) returned HTTP 200 OK.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"variant": path_suffix, "desc": desc, "status": resp.response_status},
                    payload=path_suffix,
                    proof_response=f"Variant '{path_suffix}' returned HTTP {resp.response_status}",
                    confidence=80,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C056PathNormalization)
