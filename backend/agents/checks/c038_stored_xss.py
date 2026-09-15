"""C038 — Stored XSS Verification Check for AihaX."""

from __future__ import annotations

import json
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


class C038StoredXSS(BaseCheck):
    contract = CheckContract(
        id="C038_Stored_XSS",
        name="Stored XSS Verification",
        category=CheckCategory.XSS,
        description="Detects Stored / Persistent Cross-Site Scripting (XSS) where benign canary HTML tags submitted via POST/PUT requests persist in the database and render unencoded on subsequent GET requests.",
        severity=Severity.HIGH,
        vulnerability_type="Stored Cross-Site Scripting",
        cwe="CWE-79",
        owasp_category="A03:2021-Injection",
        security_property="Persisted data rendered to clients must be HTML-encoded or sanitized with an established HTML sanitizer",
        remediation_guidance="Sanitize stored rich text using a hardened sanitizer (e.g. DOMPurify) and contextual output encoding.",
        references=[
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://portswigger.net/web-security/cross-site-scripting/stored",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "persisted_canary"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        canary_tag = "<aihax-stored-canary-888>"
        post_body = json.dumps({"comment": canary_tag, "content": canary_tag, "message": canary_tag, "text": canary_tag})

        # Step 1: Submit POST data containing canary
        post_spec = RequestSpec(
            url=target_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=post_body,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        post_resp = await request_engine.execute(post_spec)
        if not post_resp.success:
            return None

        # Step 2: Fetch target URL via GET to check persistence
        get_spec = RequestSpec(
            url=target_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        get_resp = await request_engine.execute(get_spec)
        if not get_resp.success:
            return None

        get_body = get_resp.response_body or ""
        if canary_tag in get_body and "&lt;aihax-stored-canary-888&gt;" not in get_body:
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=Severity.HIGH,
                candidate_reason=f"Stored XSS confirmed: Canary tag '{canary_tag}' submitted via POST was persisted and rendered unescaped on GET.",
                request_ids=[post_resp.request_id, get_resp.request_id],
                evidence_ids=[post_resp.evidence_id, get_resp.evidence_id],
                observed_data={"persisted_canary": canary_tag},
                payload=canary_tag,
                proof_response=f"Persisted Unencoded Tag in GET Response: {canary_tag}",
                confidence=95,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C038StoredXSS)
