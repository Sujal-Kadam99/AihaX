"""C032 — Local File Inclusion (LFI) Indicators Check for AihaX."""

from __future__ import annotations

import base64
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


class C032LocalFileInclusion(BaseCheck):
    contract = CheckContract(
        id="C032_Local_File_Inclusion",
        name="Local File Inclusion Indicators",
        category=CheckCategory.INJECTION,
        description="Detects Local File Inclusion (LFI) indicators using stream wrappers (e.g. php://filter/convert.base64-encode) that return base64 encoded local application source code.",
        severity=Severity.HIGH,
        vulnerability_type="Local File Inclusion",
        cwe="CWE-98",
        owasp_category="A03:2021-Injection",
        security_property="File inclusion mechanisms must only include static, pre-whitelisted internal view files",
        remediation_guidance="Do not pass user-supplied file names directly into include/require/readfile directives; map input keys to an explicit allowlist.",
        references=[
            "https://cwe.mitre.org/data/definitions/98.html",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "decoded_source_snippet"],
        destructive=False,
    )

    LFI_PROBES = [
        ("php://filter/convert.base64-encode/resource=index.php", "PHP Base64 Wrapper (index.php)"),
        ("php://filter/convert.base64-encode/resource=config.php", "PHP Base64 Wrapper (config.php)"),
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
            params = {"page": ["home"]}

        for param_name in list(params.keys()):
            for payload, technique in self.LFI_PROBES:
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
                # Look for base64 encoded strings in body that decode to PHP code (e.g. <?php)
                b64_matches = re.findall(r"[A-Za-z0-9+/=]{40,}", body)
                for candidate_b64 in b64_matches:
                    try:
                        decoded = base64.b64decode(candidate_b64).decode("utf-8", errors="ignore")
                        if "<?php" in decoded or "require" in decoded or "function" in decoded:
                            snippet = decoded[:150].replace("\n", " ")
                            return CheckResult(
                                check_id=self.contract.id,
                                title=self.contract.name,
                                target=target_url,
                                affected_url=test_url,
                                affected_param=param_name,
                                vulnerability_type=self.contract.vulnerability_type,
                                severity=Severity.HIGH,
                                candidate_reason=f"LFI wrapper payload successfully returned base64-encoded source code via parameter '{param_name}'.",
                                request_ids=[resp.request_id],
                                evidence_ids=[resp.evidence_id],
                                observed_data={"param": param_name, "decoded_snippet": snippet},
                                payload=payload,
                                proof_response=f"Decoded Source Snippet: {snippet}",
                                confidence=95,
                                verification_status="CANDIDATE",
                            )
                    except Exception:
                        pass

        return None


# Register check
registry.register(C032LocalFileInclusion)
