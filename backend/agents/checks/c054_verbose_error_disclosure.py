"""C054 — Verbose Error / Stack Trace Disclosure Check for AihaX."""

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


class C054VerboseErrorDisclosure(BaseCheck):
    contract = CheckContract(
        id="C054_Verbose_Error_Disclosure",
        name="Verbose Error / Stack Trace Disclosure",
        category=CheckCategory.MISCONFIG,
        description="Detects verbose server error messages and internal stack trace disclosures revealing backend file paths, framework versions, or internal method signatures.",
        severity=Severity.LOW,
        vulnerability_type="Information Disclosure",
        cwe="CWE-209",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="Production applications must present generic error pages and suppress detailed exception stack traces",
        remediation_guidance="Configure custom error pages (e.g. customErrors mode=\"On\" or debug=False) to prevent stack trace leaks to end users.",
        references=[
            "https://cwe.mitre.org/data/definitions/209.html",
            "https://owasp.org/www-community/Improper_Error_Handling",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "stack_trace_snippet"],
        destructive=False,
    )

    STACK_PATTERNS = [
        ("Python Traceback", re.compile(r"Traceback \(most recent call last\):", re.I)),
        ("Java Stack Trace", re.compile(r"java\.lang\.[a-zA-Z0-9_]+Exception:", re.I)),
        ("Java Catalina Trace", re.compile(r"at org\.apache\.catalina\.", re.I)),
        ("ASP.NET Yellow Screen", re.compile(r"Server Error in '/' Application\.|\[NullReferenceException:", re.I)),
        ("PHP Fatal Error", re.compile(r"Fatal error:\s*Uncaught exception", re.I)),
        ("Django Debug Page", re.compile(r"You're seeing this error because you have <code>DEBUG = True</code>", re.I)),
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        # Trigger potential exception with malformed query param or invalid method
        test_url = f"{target_url.rstrip('/')}/?aihax_error_probe[]=invalid_array_type"
        spec = RequestSpec(
            url=test_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp = await request_engine.execute(spec)
        if not resp.success:
            return None

        body = resp.response_body or ""
        for frame_name, pat in self.STACK_PATTERNS:
            match = pat.search(body)
            if match:
                snippet = body[max(0, match.start() - 20) : min(len(body), match.end() + 80)].replace("\n", " ")
                return CheckResult(
                    check_id=self.contract.id,
                    title=f"{self.contract.name} ({frame_name})",
                    target=target_url,
                    affected_url=test_url,
                    vulnerability_type=self.contract.vulnerability_type,
                    severity=Severity.LOW,
                    candidate_reason=f"Verbose internal exception disclosure detected: {frame_name} leaked in response.",
                    request_ids=[resp.request_id],
                    evidence_ids=[resp.evidence_id],
                    observed_data={"frame_name": frame_name, "snippet": snippet},
                    payload="?aihax_error_probe[]=invalid_array_type",
                    proof_response=f"Stack Trace Disclosed: {snippet}",
                    confidence=95,
                    verification_status="CANDIDATE",
                )

        return None


# Register check
registry.register(C054VerboseErrorDisclosure)
