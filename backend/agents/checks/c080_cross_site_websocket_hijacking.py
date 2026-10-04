"""C080 — Cross-Site WebSocket Hijacking (CSWSH) Check for AihaX."""

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


class C080CrossSiteWebSocketHijacking(BaseCheck):
    contract = CheckContract(
        id="C080_Cross_Site_WebSocket_Hijacking",
        name="Cross-Site WebSocket Hijacking (CSWSH)",
        category=CheckCategory.AUTH,
        description="Detects WebSocket handshake endpoints that establish connections without validating the Origin header or requiring CSRF tokens.",
        severity=Severity.HIGH,
        vulnerability_type="Cross-Site WebSocket Hijacking",
        cwe="CWE-1385",
        owasp_category="A01:2021-Broken Access Control",
        security_property="WebSocket upgrade requests must validate the Origin header against trusted domains or require unpredictable anti-CSRF tokens.",
        remediation_guidance="Validate the Origin header strictly during the WebSocket handshake and reject untrusted cross-origin requests.",
        references=["https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking"],
        verification_strategy="cswsh",
        required_evidence=["affected_url", "proof_request"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        untrusted_origin = "https://evil-attacker.test"
        
        # Test WebSocket handshake with untrusted Origin
        spec = RequestSpec(
            url=target_url,
            method="GET",
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
                "Origin": untrusted_origin,
            },
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        resp_evidence = await request_engine.execute(spec)
        if not resp_evidence.success:
            return None

        status = resp_evidence.response_status
        headers_lower = {k.lower(): v for k, v in resp_evidence.response_headers.items()}
        upgrade = headers_lower.get("upgrade", "").lower()

        # If handshake was accepted (101 Switching Protocols or Upgrade header accepted)
        if status == 101 or "websocket" in upgrade:
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=self.contract.severity,
                candidate_reason=f"Server accepted WebSocket upgrade from untrusted Origin '{untrusted_origin}' (HTTP {status}).",
                request_ids=[resp_evidence.request_id],
                evidence_ids=[resp_evidence.evidence_id],
                observed_data={
                    "response_status": status,
                    "upgrade_header": upgrade,
                    "sec_websocket_accept": headers_lower.get("sec-websocket-accept", ""),
                },
                payload=f"Origin: {untrusted_origin}",
                proof_request=f"GET {target_url} HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: {untrusted_origin}",
                proof_response=f"HTTP/1.1 {status} Switching Protocols\r\nUpgrade: websocket",
                confidence=80,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C080CrossSiteWebSocketHijacking)
