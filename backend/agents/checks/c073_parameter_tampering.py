"""C073 — Price / Parameter Tampering Vulnerability Check for AihaX."""

from __future__ import annotations

import json
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


class C073ParameterTampering(BaseCheck):
    contract = CheckContract(
        id="C073_Parameter_Tampering",
        name="Price / Parameter Tampering Vulnerability",
        category=CheckCategory.BUSINESS_LOGIC,
        description="Detects business logic vulnerabilities where modifying client-controlled price, discount, or quantity parameters (e.g. amount=-1, price=0.01) is accepted by the server without server-side validation.",
        severity=Severity.HIGH,
        vulnerability_type="Business Logic Flaw",
        cwe="CWE-472",
        owasp_category="A04:2021-Insecure Design",
        security_property="Financial and business transaction values must be computed and validated strictly on the server",
        remediation_guidance="Calculate item prices and discounts on the server side using database records rather than trusting values submitted by the client.",
        references=[
            "https://cwe.mitre.org/data/definitions/472.html",
            "https://owasp.org/www-community/attacks/Parameter_Tampering",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "tampered_value"],
        destructive=False,
    )

    TAMPER_PARAMS = ["price", "amount", "cost", "total", "discount", "quantity"]

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in list(params.keys()):
            if any(k in param_name.lower() for k in self.TAMPER_PARAMS):
                # Tamper value to negative or fractional zero
                tampered_val = "0.01"
                test_params = dict(params)
                test_params[param_name] = [tampered_val]
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

                # If server accepts the tampered numeric value with 200 OK
                if resp.response_status == 200:
                    return CheckResult(
                        check_id=self.contract.id,
                        title=self.contract.name,
                        target=target_url,
                        affected_url=test_url,
                        affected_param=param_name,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.HIGH,
                        candidate_reason=f"Server accepted tampered financial/quantity parameter '{param_name}={tampered_val}' with HTTP 200 OK.",
                        request_ids=[resp.request_id],
                        evidence_ids=[resp.evidence_id],
                        observed_data={"parameter": param_name, "tampered_val": tampered_val},
                        payload=f"{param_name}={tampered_val}",
                        proof_response=f"Tampered value '{param_name}={tampered_val}' accepted (HTTP 200)",
                        confidence=80,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C073ParameterTampering)
