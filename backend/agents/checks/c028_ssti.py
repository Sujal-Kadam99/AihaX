"""C028 — Server-Side Template Injection (SSTI) Check for AihaX."""

from __future__ import annotations

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


class C028ServerSideTemplateInjection(BaseCheck):
    contract = CheckContract(
        id="C028_SSTI",
        name="Server-Side Template Injection",
        category=CheckCategory.INJECTION,
        description="Detects Server-Side Template Injection (SSTI) in template engines (Jinja2, Twig, Freemarker, Smarty, ERB) via deterministic mathematical expression evaluation (e.g. {{7*7}} -> 49).",
        severity=Severity.CRITICAL,
        vulnerability_type="Template Injection",
        cwe="CWE-1336",
        owasp_category="A03:2021-Injection",
        security_property="User input must never be evaluated dynamically as raw template engine code",
        remediation_guidance="Pass user input strictly as data parameters to templates rather than concatenating user input into template strings.",
        references=[
            "https://cwe.mitre.org/data/definitions/1336.html",
            "https://portswigger.net/web-security/server-side-template-injection",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "evaluated_expression"],
        destructive=False,
    )

    SSTI_PROBES = [
        ("{{31330+7}}", "31337", "Jinja2/Twig"),
        ("${31330+7}", "31337", "Freemarker/MVEL"),
        ("<%= 31330+7 %>", "31337", "ERB/Ruby"),
        ("#{31330+7}", "31337", "Thymeleaf/Spring"),
        ("{{7*7}}", "49", "Jinja2/Twig"),
        ("${7*7}", "49", "Freemarker/MVEL"),
    ]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        # Step 1: Fetch baseline to prevent static number collisions
        base_spec = RequestSpec(
            url=target_url,
            method="GET",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        base_resp = await request_engine.execute(base_spec)
        base_body = base_resp.response_body if base_resp.success else ""

        parsed = urlparse(target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            params = {"name": ["guest"]}

        for param_name in list(params.keys()):
            for probe, expected_val, engine_hint in self.SSTI_PROBES:
                # If the baseline already contains this expected string, skip this probe
                if expected_val in base_body:
                    continue
                test_params = dict(params)
                test_params[param_name] = [probe]
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
                # If calculated result 49 is in body and the raw probe {{7*7}} is NOT reflected literally
                if expected_val in body and probe not in body:
                    return CheckResult(
                        check_id=self.contract.id,
                        title=f"{self.contract.name} ({engine_hint})",
                        target=target_url,
                        affected_url=test_url,
                        affected_param=param_name,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.CRITICAL,
                        candidate_reason=f"Template expression '{probe}' was dynamically evaluated to '{expected_val}' ({engine_hint}) on parameter '{param_name}'.",
                        request_ids=[resp.request_id],
                        evidence_ids=[resp.evidence_id],
                        observed_data={"param": param_name, "probe": probe, "evaluated_val": expected_val, "engine": engine_hint},
                        payload=probe,
                        proof_response=f"Expression '{probe}' evaluated to '{expected_val}' in response body",
                        confidence=95,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C028ServerSideTemplateInjection)
