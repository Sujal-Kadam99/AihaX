"""C086 — Insecure Deserialization Indicators Check for AihaX."""

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


class C086InsecureDeserializationIndicators(BaseCheck):
    contract = CheckContract(
        id="C086_Insecure_Deserialization_Indicators",
        name="Insecure Deserialization Indicators",
        category=CheckCategory.INJECTION,
        description="Detects endpoints accepting untrusted serialized objects (Java, Python pickle, PHP, .NET) without integrity signing or type constraints.",
        severity=Severity.HIGH,
        vulnerability_type="Insecure Deserialization",
        cwe="CWE-502",
        owasp_category="A08:2021-Software and Data Integrity Failures",
        security_property="Applications must not deserialize untrusted data streams without cryptographic integrity verification and strict type allowlisting.",
        remediation_guidance="Avoid native serialization formats; use standard structured formats like JSON/Protocol Buffers with strict schemas, or enforce HMAC signing.",
        references=["https://portswigger.net/web-security/deserialization"],
        verification_strategy="insecure_deserialization",
        required_evidence=["affected_url", "proof_request"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        # Bounded canary probe testing serialized format processing
        # Java magic header bytes base64: rO0ABXNy...
        # PHP serialized object: O:8:"stdClass":0:{}
        # Python pickle: b'\x80\x04\x95\r\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x04test\x94\x8c\x04safe\x94s.'
        php_probe = 'O:8:"stdClass":0:{}'
        spec = RequestSpec(
            url=target_url,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=f"data={php_probe}",
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )

        resp_evidence = await request_engine.execute(spec)
        if not resp_evidence.success:
            return None

        body = resp_evidence.response_body or ""
        # Check for deserialization stack traces or unpickling/unserialize error messages
        deserialization_indicators = [
            "unserialize()",
            "java.io.InvalidClassException",
            "java.io.StreamCorruptedException",
            "java.io.ObjectInputStream",
            "org.apache.commons.collections",
            "UnpicklingError",
            "pickle.Unpickler",
            "BinaryFormatter",
            "TypeNameHandling",
        ]

        if any(ind.lower() in body.lower() for ind in deserialization_indicators):
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=self.contract.severity,
                candidate_reason="Server response revealed active object deserialization parser indicators in response.",
                request_ids=[resp_evidence.request_id],
                evidence_ids=[resp_evidence.evidence_id],
                observed_data={"deserialization_stack_indicator": True},
                payload=php_probe,
                proof_request=f"POST {target_url} HTTP/1.1\r\n\r\ndata={php_probe}",
                proof_response=f"HTTP/1.1 {resp_evidence.response_status}\r\n\r\n{body[:300]}",
                confidence=75,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C086InsecureDeserializationIndicators)
