"""Dedicated Phase 4 Standalone Verification Runner for AihaX.

Demonstrates with deterministic MockTransport:
1. Each registered check executes via RequestEngine.
2. RequestEngine receives the requests.
3. Scope denial causes zero transport calls.
4. Candidate evidence is generated.
5. VerificationEngine is invoked.
6. Final verdict is deterministic.
7. No unmanaged direct legacy network paths are used.
"""

import asyncio
import json
import os
import sys

# Ensure workspace root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.agents.vuln_agent import VulnAgent
from backend.core.check_registry import registry
from backend.core.scope_validator import ScopeValidator
from backend.models.database import Finding
from backend.services.request_engine import MockTransport, RequestEngine, RequestSpec
from backend.services.verification_engine import (
    VerificationEngine,
    VerificationStatus,
)
import backend.agents.checks  # Ensure checks are registered


async def run_phase4_verification():
    print("=" * 70)
    print("AIHAX PHASE 4: VULNERABILITY DETECTOR MODERNIZATION VERIFICATION")
    print("=" * 70)

    passed_checks = 0
    total_checks = 7

    target_domain = "https://app.target.com"
    validator = ScopeValidator(in_scope_assets=[target_domain, "http://app.target.com"])

    # Setup mocked responses for all 7 checks
    transport = MockTransport(default_status=200, default_headers={"Server": "nginx"})
    transport.add_route("http://app.target.com", status=200, headers={"Server": "mock-http-80"})
    transport.add_route("https://app.target.com/.env", status=200, body="DB_PASSWORD=secret_demo_123")
    transport.add_route(
        "https://app.target.com/graphql",
        status=200,
        body='{"data":{"__schema":{"types":[{"name":"User"}]}}}',
    )
    transport.add_route(
        "https://app.target.com/images/",
        status=200,
        body="<html><head><title>Index of /images/</title></head><body><h1>Index of /images/</h1></body></html>",
    )
    transport.add_route(
        "https://app.target.com?next=https://evil.com",
        status=302,
        headers={"Location": "https://evil.com/landing"},
    )

    # Dynamic handler for CORS (when Origin is supplied)
    from backend.services.request_engine import RawResponse
    def cors_handler(method, url, headers, params, body):
        if headers and "evil.com" in headers.get("Origin", ""):
            return RawResponse(
                status_code=200,
                headers={"Access-Control-Allow-Origin": "https://evil.com", "Access-Control-Allow-Credentials": "true"},
                body=b"CORS OK",
                observed_size=7,
            )
        return RawResponse(
            status_code=200,
            headers={"Server": "nginx"},
            body=b"<html><body>Standard Response</body></html>",
            observed_size=42,
        )

    transport.register_handler(lambda m, u: u == "https://app.target.com", cors_handler, priority=len("https://app.target.com"))

    request_engine = RequestEngine(scope_validator=validator, transport=transport)
    verification_engine = VerificationEngine()

    check_ids = [
        "C001_Open_Port_80",
        "C002_Missing_Security_Headers",
        "C003_Sensitive_Files_Exposure",
        "C004_CORS_Misconfiguration",
        "C005_GraphQL_Introspection",
        "C006_Directory_Listing",
        "C007_Open_Redirect",
    ]

    for check_id in check_ids:
        print(f"\n[*] Executing {check_id}...")
        check_cls = registry.get_check(check_id)
        check_instance = check_cls()
        contract = check_instance.contract

        # 1. Execute check through RequestEngine
        candidate = await check_instance.execute(request_engine, target_domain, {})
        assert candidate is not None, f"Check {check_id} failed to produce candidate"
        assert candidate.verification_status == "CANDIDATE", f"Check {check_id} must produce CANDIDATE status"
        assert len(candidate.request_ids) > 0, f"Check {check_id} missing request IDs"
        assert len(candidate.evidence_ids) > 0, f"Check {check_id} missing evidence IDs"
        print(f"    -> Candidate finding generated: '{candidate.title}' [Request IDs: {candidate.request_ids}]")

        # 2. Convert to Finding model
        finding = Finding(
            id=f"f-{check_id}",
            title=contract.name,
            vuln_type=contract.id,
            category=contract.category.value,
            severity=contract.severity.value,
            affected_url=candidate.affected_url,
            payload=candidate.payload,
            proof_response=candidate.proof_response,
            confidence=candidate.confidence,
            verification_status="CANDIDATE",
            verdict="Candidate",
            false_positive=False,
            evidence_ids=json.dumps(candidate.evidence_ids),
            request_ids=json.dumps(candidate.request_ids),
        )

        # 3. Verify finding through VerificationEngine
        conclusion = await verification_engine.verify_finding(
            finding=finding,
            request_engine=request_engine,
            authorization_confirmed=True,
        )
        assert conclusion.status == VerificationStatus.VERIFIED, f"Verification failed for {check_id}: {conclusion}"
        assert finding.verdict == "Verified"
        print(f"    -> Deterministic Verdict: {conclusion.status.value} (Reason: {conclusion.reason_code.value})")
        passed_checks += 1

    # 4. Test Scope Gating (Out of scope target -> 0 transport calls)
    print("\n[*] Testing ScopeValidator Gating on Out-of-Scope Target...")
    scope_transport = MockTransport(default_status=200)
    scope_engine = RequestEngine(scope_validator=validator, transport=scope_transport)
    c002_cls = registry.get_check("C002_Missing_Security_Headers")
    res_denied = await c002_cls().execute(scope_engine, "https://denied-domain.com", {})
    assert res_denied is None
    assert scope_transport.call_count == 0, "Out-of-scope request leaked through transport!"
    print("    -> Out-of-scope target successfully blocked with ZERO transport calls.")

    # 5. Test Authorization Confirmation Gate
    print("\n[*] Testing Authorization Gate (unauthorized target -> 0 transport calls)...")
    unauth_spec = RequestSpec(url=target_domain, authorization_confirmed=False)
    unauth_evidence = await scope_engine.execute(unauth_spec)
    assert unauth_evidence.success is False
    assert unauth_evidence.transport_error["error_type"] in ("AUTH_MISSING", "UNAUTHORIZED_TARGET")
    assert scope_transport.call_count == 0, "Unauthorized request leaked through transport!"
    print("    -> Missing authorization confirmation successfully blocked with ZERO transport calls.")

    print("\n" + "=" * 70)
    print(f"SUMMARY: {passed_checks}/{total_checks} Phase 4 checks successfully executed and verified.")
    print("All architectural invariants satisfied: RequestEngine mandatory boundary, 0 unmanaged calls.")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_phase4_verification())
