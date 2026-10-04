"""C078 — HTTP Request Smuggling (CL.TE / TE.CL Desync) Check for AihaX."""

from __future__ import annotations

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


class C078HTTPRequestSmuggling(BaseCheck):
    contract = CheckContract(
        id="C078_HTTP_Request_Smuggling",
        name="HTTP Request Smuggling (CL.TE / TE.CL Desync)",
        category=CheckCategory.INFRASTRUCTURE,
        description="Detects parsing discrepancies between front-end and back-end HTTP servers via dual Content-Length and Transfer-Encoding headers.",
        severity=Severity.CRITICAL,
        vulnerability_type="HTTP Request Smuggling",
        cwe="CWE-444",
        owasp_category="A05:2021-Security Misconfiguration",
        security_property="Front-end and back-end proxies must uniformly parse request boundaries and reject ambiguous length headers.",
        remediation_guidance="Disable HTTP/1.1 reuse on back-end connections, enforce HTTP/2 end-to-end, or strictly reject requests containing both Content-Length and Transfer-Encoding.",
        references=["https://portswigger.net/web-security/request-smuggling"],
        verification_strategy="http_request_smuggling",
        required_evidence=["affected_url", "proof_request"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        # Bounded desync detection probe
        smuggle_body = "0\r\n\r\nG"
        spec = RequestSpec(
            url=target_url,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": "6",
                "Transfer-Encoding": "chunked",
            },
            body=smuggle_body,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        resp_evidence = await request_engine.execute(spec)
        if not resp_evidence.success:
            return None

        # Check for response anomalies / server accepting ambiguous headers without rejection
        status = resp_evidence.response_status
        headers_lower = {k.lower(): v for k, v in resp_evidence.response_headers.items()}
        
        # If server didn't immediately reject with 400 Bad Request
        if status in (200, 201, 204, 500, 502, 504):
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=self.contract.severity,
                candidate_reason=f"Server accepted dual Content-Length and Transfer-Encoding headers (HTTP {status}) without 400 rejection.",
                request_ids=[resp_evidence.request_id],
                evidence_ids=[resp_evidence.evidence_id],
                observed_data={
                    "response_status": status,
                    "server_header": headers_lower.get("server", ""),
                },
                payload="Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
                proof_request=f"POST {target_url} HTTP/1.1\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n{smuggle_body}",
                proof_response=f"HTTP/1.1 {status}\r\nServer: {headers_lower.get('server', '')}",
                confidence=70,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C078HTTPRequestSmuggling)
