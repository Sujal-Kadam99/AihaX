"""C024 — Blind SQL Injection Check for AihaX."""

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


class C024BlindSQLInjection(BaseCheck):
    contract = CheckContract(
        id="C024_Blind_SQL_Injection",
        name="Blind SQL Injection",
        category=CheckCategory.INJECTION,
        description="Detects boolean-based blind SQL injection vulnerabilities via differential content response analysis between true (AND 1=1) and false (AND 1=2) injection states.",
        severity=Severity.CRITICAL,
        vulnerability_type="Blind SQL Injection",
        cwe="CWE-89",
        owasp_category="A03:2021-Injection",
        security_property="Boolean conditions injected into parameters must not alter SQL execution logic or produce differential responses",
        remediation_guidance="Use parameterized queries across all database drivers and avoid dynamic query concatenation.",
        references=[
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://portswigger.net/web-security/sql-injection/blind",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "differential_proof"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            params = {"id": ["1"]}

        for param_name, vals in list(params.items()):
            orig_val = vals[0] if vals else "1"

            # True payload vs False payload
            true_payload = f"{orig_val} AND 1=1"
            false_payload = f"{orig_val} AND 1=2"

            # Step 1: Request True state
            p_true = dict(params)
            p_true[param_name] = [true_payload]
            url_true = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(p_true, doseq=True), parsed.fragment))
            resp_true = await request_engine.execute(RequestSpec(url=url_true, method="GET", timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0)))

            # Step 2: Request False state
            p_false = dict(params)
            p_false[param_name] = [false_payload]
            url_false = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(p_false, doseq=True), parsed.fragment))
            resp_false = await request_engine.execute(RequestSpec(url=url_false, method="GET", timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0)))

            if resp_true.success and resp_false.success:
                # Differential condition: True returns 200 with content, False returns 200 with significantly different length or different status (404/empty)
                body_true = resp_true.response_body or ""
                body_false = resp_false.response_body or ""

                len_diff = abs(len(body_true) - len(body_false))
                # Distinct structural differential
                if resp_true.response_status == 200 and (resp_false.response_status != 200 or len_diff > 100):
                    return CheckResult(
                        check_id=self.contract.id,
                        title=self.contract.name,
                        target=target_url,
                        affected_url=url_true,
                        affected_param=param_name,
                        vulnerability_type=self.contract.vulnerability_type,
                        severity=Severity.CRITICAL,
                        candidate_reason=f"Differential boolean response detected on parameter '{param_name}': True condition returned {resp_true.response_status} ({len(body_true)} bytes), False condition returned {resp_false.response_status} ({len(body_false)} bytes).",
                        request_ids=[resp_true.request_id, resp_false.request_id],
                        evidence_ids=[resp_true.evidence_id, resp_false.evidence_id],
                        observed_data={"param": param_name, "len_true": len(body_true), "len_false": len(body_false)},
                        payload=f"True: {true_payload} | False: {false_payload}",
                        proof_response=f"True state: {resp_true.response_status} ({len(body_true)}B) vs False state: {resp_false.response_status} ({len(body_false)}B)",
                        confidence=85,
                        verification_status="CANDIDATE",
                    )

        return None


# Register check
registry.register(C024BlindSQLInjection)
