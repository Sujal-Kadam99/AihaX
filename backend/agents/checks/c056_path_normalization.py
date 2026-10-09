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
        ("/admin/..;/", "/admin/", "Tomcat Matrix Parameter Semicolon (/..;/)"),
        ("/%2e%2e/", "/", "URL-encoded Dot Dot (/%2e%2e/)"),
        ("/static/..%2fadmin", "/static/admin", "Encoded Slash Traversal (..%2f)"),
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        base = target_url.rstrip("/")

        for path_suffix, baseline_path, desc in self.NORMALIZATION_VARIANTS:
            test_url = f"{base}{path_suffix}"
            baseline_url = f"{base}{baseline_path}"
            resp = await request_engine.execute(RequestSpec(
                url=test_url,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            ))
            baseline = await request_engine.execute(RequestSpec(
                url=baseline_url,
                method="GET",
                timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
            ))
            if not resp.success or not baseline.success:
                continue

            variant_body = resp.response_body or ""
            baseline_body = baseline.response_body or ""
            variant_is_generic_html = "<!doctype html" in variant_body.lower() and (
                "juice shop" in variant_body.lower() or "<app-root" in variant_body.lower()
            )
            # A 200 by itself proves only that a route exists. Require the canonical
            # protected route to deny access and the variant to return distinct content.
            if (
                resp.response_status == 200
                and baseline.response_status in (401, 403)
                and not variant_is_generic_html
                and variant_body != baseline_body
            ):
                return CheckResult(
                    check_id=self.contract.id,
                    title=f"{self.contract.name} ({desc})",
                    target=target_url,
                    affected_url=test_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.MEDIUM,
                    candidate_reason=f"Path normalization discrepancy observed: URL variant '{path_suffix}' ({desc}) returned HTTP 200 OK.",
                    request_ids=[baseline.request_id, resp.request_id],
                    evidence_ids=[baseline.evidence_id, resp.evidence_id],
                    observed_data={"variant": path_suffix, "baseline": baseline_path, "desc": desc, "status": resp.response_status, "baseline_status": baseline.response_status},
                    payload=path_suffix,
                    proof_response=f"Variant '{path_suffix}' returned HTTP {resp.response_status}",
                    confidence=80,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C056PathNormalization)
