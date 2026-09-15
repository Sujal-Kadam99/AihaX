"""C076 — Replay Attack Vulnerability Check for AihaX."""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urljoin

from backend.core.check_registry import (
    BaseCheck,
    CheckCategory,
    CheckContract,
    CheckResult,
    Severity,
    registry,
)
from backend.services.request_engine import RequestEngine, RequestSpec, RequestTimeout


class C076ReplayAttack(BaseCheck):
    contract = CheckContract(
        id="C076_Replay_Attack",
        name="Replay Attack Vulnerability",
        category=CheckCategory.BUSINESS_LOGIC,
        description="Detects whether one-time action tokens, verification codes, or signed financial transactions can be replayed and processed multiple times without nonce or timestamp invalidation.",
        severity=Severity.MEDIUM,
        vulnerability_type="Business Logic Flaw",
        cwe="CWE-294",
        owasp_category="A07:2021-Identification and Authentication Failures",
        security_property="Single-use tokens and sensitive transactional requests must enforce replay prevention via unique nonces and immediate token invalidation",
        remediation_guidance="Invalidate one-time tokens immediately upon first consumption and implement unique request nonces with short timestamp validity windows.",
        references=[
            "https://cwe.mitre.org/data/definitions/294.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html",
        ],
        verification_strategy="generic_reproducibility",
        required_evidence=["affected_url", "proof_response", "replayed_status"],
        destructive=False,
    )

    async def execute(
        self,
        request_engine: RequestEngine,
        target_url: str,
        config: Dict[str, Any],
    ) -> Optional[CheckResult]:
        payload = '{"otp": "123456", "nonce": "aihax_nonce_test_789"}'
        spec1 = RequestSpec(
            url=target_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=payload,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp1 = await request_engine.execute(spec1)
        if not resp1.success or resp1.response_status not in (200, 201):
            return None

        # Replay the identical request
        spec2 = RequestSpec(
            url=target_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=payload,
            timeout=RequestTimeout(connect=5.0, read=10.0, total=15.0),
        )
        resp2 = await request_engine.execute(spec2)
        if not resp2.success:
            return None

        # If replayed request succeeded with identical 200/201 status
        if resp2.response_status == resp1.response_status:
            return CheckResult(
                check_id=self.contract.id,
                title=self.contract.name,
                target=target_url,
                affected_url=target_url,
                vulnerability_type=self.contract.vulnerability_type,
                severity=Severity.MEDIUM,
                candidate_reason=f"Action accepted replayed single-use transaction payload twice with identical HTTP {resp2.response_status}.",
                request_ids=[resp1.request_id, resp2.request_id],
                evidence_ids=[resp1.evidence_id, resp2.evidence_id],
                observed_data={"first_status": resp1.response_status, "replayed_status": resp2.response_status},
                payload=payload,
                proof_response=f"Initial: HTTP {resp1.response_status} | Replay: HTTP {resp2.response_status}",
                confidence=80,
                verification_status="CANDIDATE",
            )

        return None


# Register check
registry.register(C076ReplayAttack)
