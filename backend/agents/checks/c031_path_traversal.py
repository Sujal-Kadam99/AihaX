"""C031 — Path Traversal Check for AihaX."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C031PathTraversal(BaseCheck):
    contract = CheckContract(
        id="C031_Path_Traversal",
        name="Path Traversal",
        category=CheckCategory.INJECTION,
        description="Detects directory and path traversal vulnerabilities that allow reading arbitrary files outside the web root (e.g. /etc/passwd or C:\\Windows\\win.ini).",
        severity=Severity.HIGH,
        vulnerability_type="Path Traversal",
        cwe="CWE-22",
        owasp_category="A01:2021-Broken Access Control",
        security_property="File path parameters must be sanitized and constrained strictly to an authorized base directory",
        remediation_guidance="Use secure path resolution APIs (e.g. Path.resolve()) to verify that the canonical path resides within the intended base directory.",
        references=[
            "https://cwe.mitre.org/data/definitions/22.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "file_marker"],
        destructive=False,
    )

    TRAVERSAL_PAYLOADS = [
        ("../../../../etc/passwd", re.compile(r"root:.*:0:0:", re.I), "Linux /etc/passwd"),
        ("..\\..\\..\\..\\windows\\win.ini", re.compile(r"\[(?:fonts|extensions|files)\]", re.I), "Windows win.ini"),
        ("/etc/passwd", re.compile(r"root:.*:0:0:", re.I), "Absolute /etc/passwd"),
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            params = {"file": ["about.html"]}

        for param_name in list(params.keys()):
            for payload, marker_pat, os_hint in self.TRAVERSAL_PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                spec = RequestSpec(
                    url=test_url,
                    method="GET",
                    timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
                )
                resp = await request_engine.execute(spec)
                if not resp.success:
                    continue

                body = resp.response_body or ""
                match = marker_pat.search(body)
                if match:
                    snippet = body[max(0, match.start() - 20) : min(len(body), match.end() + 60)].replace("\n", " ")
                    return CheckResult(
                        check_id=self.contract.id,
                        title=f"{self.contract.name} ({os_hint})",
                        target=target_url,
                        affected_url=test_url,
                        affected_param=param_name,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.HIGH,
                        candidate_reason=f"Path traversal payload '{payload}' successfully read {os_hint} via parameter '{param_name}'.",
                        request_ids=[resp.request_id],
                        evidence_ids=[resp.evidence_id],
                        observed_data={"param": param_name, "os_hint": os_hint, "snippet": snippet},
                        payload=payload,
                        proof_response=f"Path Traversal Evidence ({os_hint}): {snippet}",
                        confidence=95,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C031PathTraversal)
