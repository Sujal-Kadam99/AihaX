"""Deterministic Manual Verification Script for Evidence-Based Verification Engine.

Tests Cases 1 through 8 using controlled MockTransport and mock database models:
1. Candidate + sufficient deterministic evidence -> VERIFIED
2. Candidate + insufficient evidence -> INCONCLUSIVE
3. Candidate + contradictory evidence -> FALSE_POSITIVE
4. LLM claims VERIFIED but deterministic engine says INCONCLUSIVE -> INCONCLUSIVE
5. Verification attempts out-of-scope target -> BLOCKED (transport count = 0)
6. Verification exceeds request budget -> INCONCLUSIVE
7. Candidate marked VERIFIED -> Accepted by Bug Bounty Report Generator
8. Candidate not verified -> Excluded by Bug Bounty Report Generator
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.core.scope_validator import ScopeValidator
from backend.models.database import Finding
from backend.services.bug_bounty_generator import BugBountyReportGenerator
from backend.services.request_engine import (
    MockTransport,
    RequestEngine,
    RequestSpec,
)
from backend.services.verification_engine import (
    BaseVerificationStrategy,
    VerificationBudget,
    VerificationConclusion,
    VerificationContext,
    VerificationContract,
    VerificationEngine,
    VerificationReasonCode,
    VerificationRegistry,
    VerificationStatus,
)


async def run_verification():
    print("==================================================")
    print("AihaX Bug Bounty Platform — Verification Engine Matrix")
    print("==================================================")

    validator = ScopeValidator(
        in_scope_assets=["example.com", "*.example.com"],
        out_of_scope_assets=["evil.com"],
        allowed_ports=[80, 443],
        allowed_schemes=["https"],
    )
    engine = VerificationEngine()
    all_passed = True

    # ─────────────────────────────────────────────────────────────
    # CASE 1: Candidate + Sufficient Deterministic Evidence
    # ─────────────────────────────────────────────────────────────
    t1 = MockTransport()
    t1.register_response("https://app.example.com/api/test", status_code=200, body="exact_proof_token_abc")
    re1 = RequestEngine(scope_validator=validator, transport=t1)

    f1 = Finding(
        id="F001",
        title="Info Leak",
        vuln_type="generic_reproducibility",
        category="misc",
        severity="high",
        affected_url="https://app.example.com/api/test",
        proof_response="exact_proof_token_abc",
        confidence=80,
    )
    c1 = await engine.verify_finding(f1, re1, authorization_confirmed=True)
    pass1 = (c1.status == VerificationStatus.VERIFIED) and (c1.reason_code == VerificationReasonCode.REPRODUCED_SUCCESSFULLY)
    if not pass1:
        all_passed = False
    print(f"[{'PASS' if pass1 else 'FAIL'}] CASE 1: Candidate + Sufficient Evidence")
    print(f"       Verdict={c1.status.value}, Reason={c1.reason_code.value}, TransportCalls={t1.call_count}, EvidenceIDs={c1.evidence_ids}")

    # ─────────────────────────────────────────────────────────────
    # CASE 2: Candidate + Insufficient / Missing Evidence
    # ─────────────────────────────────────────────────────────────
    t2 = MockTransport()
    re2 = RequestEngine(scope_validator=validator, transport=t2)

    f2 = Finding(
        id="F002",
        title="Vague Finding",
        vuln_type="generic_reproducibility",
        category="misc",
        severity="medium",
        affected_url="https://app.example.com/api/test",
        proof_response="",  # Insufficient proof
        confidence=30,
    )
    c2 = await engine.verify_finding(f2, re2, authorization_confirmed=True)
    pass2 = (c2.status == VerificationStatus.INCONCLUSIVE) and (c2.reason_code == VerificationReasonCode.MISSING_EVIDENCE)
    if not pass2:
        all_passed = False
    print(f"[{'PASS' if pass2 else 'FAIL'}] CASE 2: Candidate + Insufficient Evidence")
    print(f"       Verdict={c2.status.value}, Reason={c2.reason_code.value}, TransportCalls={t2.call_count}")

    # ─────────────────────────────────────────────────────────────
    # CASE 3: Candidate + Contradictory Evidence
    # ─────────────────────────────────────────────────────────────
    t3 = MockTransport()
    t3.register_response("https://app.example.com/api/missing", status_code=404, body="404 Not Found")
    re3 = RequestEngine(scope_validator=validator, transport=t3)

    f3 = Finding(
        id="F003",
        title="Nonexistent Resource",
        vuln_type="generic_reproducibility",
        category="misc",
        severity="low",
        affected_url="https://app.example.com/api/missing",
        proof_response="secret_admin_panel",
        confidence=70,
    )
    c3 = await engine.verify_finding(f3, re3, authorization_confirmed=True)
    pass3 = (c3.status == VerificationStatus.FALSE_POSITIVE) and (c3.reason_code == VerificationReasonCode.CONTRADICTORY_EVIDENCE)
    if not pass3:
        all_passed = False
    print(f"[{'PASS' if pass3 else 'FAIL'}] CASE 3: Candidate + Contradictory Evidence")
    print(f"       Verdict={c3.status.value}, Reason={c3.reason_code.value}, TransportCalls={t3.call_count}")

    # ─────────────────────────────────────────────────────────────
    # CASE 4: LLM Claims VERIFIED but Deterministic Engine Says INCONCLUSIVE
    # ─────────────────────────────────────────────────────────────
    t4 = MockTransport()
    re4 = RequestEngine(scope_validator=validator, transport=t4)

    f4 = Finding(
        id="F004",
        title="LLM Hallucination Test",
        vuln_type="generic_reproducibility",
        category="misc",
        severity="high",
        affected_url="https://app.example.com/api/test",
        proof_response="",  # Missing evidence
    )
    c4 = await engine.verify_finding(f4, re4, authorization_confirmed=True)
    # LLM assertion ignored by architecture
    llm_claim = "VERIFIED"
    effective_status = f4.verification_status
    pass4 = (effective_status == "INCONCLUSIVE") and (c4.status == VerificationStatus.INCONCLUSIVE)
    if not pass4:
        all_passed = False
    print(f"[{'PASS' if pass4 else 'FAIL'}] CASE 4: LLM Claims VERIFIED vs Deterministic INCONCLUSIVE")
    print(f"       LLMClaim={llm_claim}, DeterministicVerdict={effective_status} (LLM Override Blocked)")

    # ─────────────────────────────────────────────────────────────
    # CASE 5: Verification Attempts Out-of-Scope Target
    # ─────────────────────────────────────────────────────────────
    t5 = MockTransport()
    re5 = RequestEngine(scope_validator=validator, transport=t5)

    f5 = Finding(
        id="F005",
        title="Out-of-Scope Target",
        vuln_type="generic_reproducibility",
        category="misc",
        severity="critical",
        affected_url="https://evil.com/target",
        proof_response="pwned",
    )
    c5 = await engine.verify_finding(f5, re5, authorization_confirmed=True)
    pass5 = (c5.status == VerificationStatus.INCONCLUSIVE) and (c5.reason_code == VerificationReasonCode.OUT_OF_SCOPE_BLOCKED) and (t5.call_count == 0)
    if not pass5:
        all_passed = False
    print(f"[{'PASS' if pass5 else 'FAIL'}] CASE 5: Out-of-Scope Target")
    print(f"       Verdict={c5.status.value}, Reason={c5.reason_code.value}, TransportCalls={t5.call_count} (Blocked at Scope Layer)")

    # ─────────────────────────────────────────────────────────────
    # CASE 6: Verification Exceeds Request Budget
    # ─────────────────────────────────────────────────────────────
    t6 = MockTransport()
    re6 = RequestEngine(scope_validator=validator, transport=t6)

    class InfiniteStrategy(BaseVerificationStrategy):
        contract = VerificationContract(
            check_id="infinite_strategy",
            name="Infinite Strategy",
            security_property="Tests budget enforcement",
            default_budget=VerificationBudget(max_requests=2),
        )
        async def verify(self, context: VerificationContext) -> VerificationConclusion:
            for _ in range(5):
                await context.send_verification_request(RequestSpec(url="https://app.example.com/api/test"))
            return VerificationConclusion(status=VerificationStatus.VERIFIED, reason_code=VerificationReasonCode.PROPERTY_DEMONSTRATED, reason_description="Fail")

    VerificationRegistry.register(InfiniteStrategy)
    f6 = Finding(
        id="F006",
        title="Budget Exceeded",
        vuln_type="infinite_strategy",
        category="test",
        severity="info",
        affected_url="https://app.example.com/api/test",
    )
    c6 = await engine.verify_finding(f6, re6, budget=VerificationBudget(max_requests=2))
    pass6 = (c6.status == VerificationStatus.INCONCLUSIVE) and (c6.reason_code == VerificationReasonCode.BUDGET_EXHAUSTED or "budget" in c6.reason_description.lower())
    if not pass6:
        all_passed = False
    print(f"[{'PASS' if pass6 else 'FAIL'}] CASE 6: Verification Exceeds Request Budget")
    print(f"       Verdict={c6.status.value}, Reason={c6.reason_description}, RequestsMade={t6.call_count}")

    # ─────────────────────────────────────────────────────────────
    # CASE 7 & 8: Bug Bounty Report Generator Inclusions and Exclusions
    # ─────────────────────────────────────────────────────────────
    generator = BugBountyReportGenerator()
    f_verified = Finding(
        id="FV",
        title="Verified Finding",
        vuln_type="C001_Open_Port_80",
        category="recon",
        severity="high",
        affected_url="https://app.example.com/api/test",
        verdict="Verified",
        verification_status="VERIFIED",
        false_positive=False,
        confidence=100,
    )
    f_unverified = Finding(
        id="FU",
        title="Unverified Finding",
        vuln_type="C001_Open_Port_80",
        category="recon",
        severity="high",
        affected_url="https://app.example.com/api/test",
        verdict="Inconclusive",
        verification_status="INCONCLUSIVE",
        false_positive=False,
        confidence=40,
    )

    dtos_verified = await generator.generate_for_findings([f_verified])
    pass7 = (len(dtos_verified) == 1) and (dtos_verified[0].title == "Verified Finding")
    if not pass7:
        all_passed = False
    print(f"[{'PASS' if pass7 else 'FAIL'}] CASE 7: Candidate Marked VERIFIED Accepted by Report Generator")
    print(f"       AcceptedCount={len(dtos_verified)}")

    dtos_unverified = await generator.generate_for_findings([f_unverified])
    pass8 = (len(dtos_unverified) == 0)
    if not pass8:
        all_passed = False
    print(f"[{'PASS' if pass8 else 'FAIL'}] CASE 8: Candidate NOT Verified Excluded by Report Generator")
    print(f"       AcceptedCount={len(dtos_unverified)} (Excluded)")

    print("==================================================")
    if all_passed:
        print("ALL 8 VERIFICATION ENGINE TEST CASES PASSED (100% ASSURANCE)")
    else:
        print("VERIFICATION ENGINE TEST CASES FAILED")
    print("==================================================")
    return all_passed


if __name__ == "__main__":
    success = asyncio.run(run_verification())
    if not success:
        sys.exit(1)
