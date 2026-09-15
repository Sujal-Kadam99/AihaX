"""C035 — Expression Language (EL) Injection Check for AihaX."""

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


class C035ELInjection(BaseCheck):
    contract = CheckContract(
        id="C035_EL_Injection",
        name="Expression Language Injection",
        category=CheckCategory.INJECTION,
        description="Detects Spring Expression Language (SpEL), OGNL, or Java Unified Expression Language (JUEL) injection vulnerabilities through mathematical expression evaluation.",
        severity=Severity.CRITICAL,
        vulnerability_type="Expression Language Injection",
        cwe="CWE-917",
        owasp_category="A03:2021-Injection",
        security_property="User parameters must never be evaluated dynamically within Java Expression Language interpreters",
        remediation_guidance="Do not evaluate untrusted user input with SpEL or OGNL parser contexts, and disable dynamic expression evaluation.",
        references=[
            "https://cwe.mitre.org/data/definitions/917.html",
            "https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "evaluated_expression"],
        destructive=False,
    )

    EL_PROBES = [
        ("${31330+7}", "31337", "JSP EL / JUEL"),
        ("#{31330+7}", "31337", "JSF / Unified EL"),
        ("%{(31330+7)}", "31337", "Struts OGNL"),
        ("T(java.lang.Math).min(10,20)", "10", "Spring SpEL"),
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
            params = {"expr": ["test"]}

        for param_name in list(params.keys()):
            for probe, expected_val, el_type in self.EL_PROBES:
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
                # If calculated result is present and raw probe is not merely reflected literally
                if expected_val in body and probe not in body:
                    return CheckResult(
                        check_id=self.contract.id,
                        title=f"{self.contract.name} ({el_type})",
                        target=target_url,
                        affected_url=test_url,
                        affected_param=param_name,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.CRITICAL,
                        candidate_reason=f"Expression language payload '{probe}' evaluated to '{expected_val}' ({el_type}) on parameter '{param_name}'.",
                        request_ids=[resp.request_id],
                        evidence_ids=[resp.evidence_id],
                        observed_data={"param": param_name, "probe": probe, "evaluated_val": expected_val, "el_type": el_type},
                        payload=probe,
                        proof_response=f"Expression '{probe}' evaluated to '{expected_val}' in response body",
                        confidence=95,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C035ELInjection)
