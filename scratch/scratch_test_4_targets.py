import asyncio
import json
from datetime import datetime, timezone

from backend.services.vulnerability_execution_engine import VulnerabilityExecutionEngine, VulnerabilityHypothesis, ExecutionMode, FindingStatus
from backend.services.verification_engine import VerificationEngine
from backend.models.database import Finding
from backend.services.request_engine import RequestEngine, AiohttpTransport
from backend.core.scope_validator import ScopeValidator

async def test_target(engine, hyp, verification_engine, expected_status="EXPLOITABLE"):
    print(f"\n--- Testing {hyp.check_id} against {hyp.endpoint} ---")
    print("Running execution engine...")
    evidence = await engine.execute_hypothesis(hyp, mode=ExecutionMode.SIMULATION)
    print(f"Execution Engine Result: {evidence.result_status}")
    if evidence.explanation:
        print(f"Explanation: {evidence.explanation}")

    if evidence.result_status not in [FindingStatus.DETECTED.value, FindingStatus.EXPLOITABLE.value]:
        print("Test failed at execution stage.")
        return

    proof_req = f"{evidence.request_metadata.get('method')} {evidence.request_metadata.get('endpoint')}\n"
    for k, v in evidence.request_metadata.get('headers', {}).items():
        proof_req += f"{k}: {v}\n"
    if evidence.request_metadata.get('body'):
        body = evidence.request_metadata.get('body')
        proof_req += f"\n{body if isinstance(body, str) else json.dumps(body)}"

    finding = Finding(
        id=f"find-{hyp.check_id}",
        scan_id="scan-123",
        agent_id=1,
        title=f"{hyp.check_id} Detected",
        vuln_type=hyp.check_id,
        category="Injection",
        severity="High",
        confidence=90,
        affected_url=evidence.request_metadata.get('endpoint') or evidence.endpoint or hyp.endpoint,
        affected_param=hyp.parameter,
        payload=evidence.request_metadata.get('payload', ''),
        proof_request=proof_req,
        proof_response=evidence.response_metadata.get('body', str(evidence.response_metadata)),
        false_positive=False,
    )
    
    print("Running verification engine...")
    conclusion = await verification_engine.verify_finding(
        finding=finding,
        request_engine=engine.request_engine,
        authorization_confirmed=True
    )
    print(f"Verification Engine Result: {conclusion.status.value}")
    print(f"Reason: {conclusion.reason_code}")
    print(f"Description: {conclusion.reason_description}")
    print(f"Confidence: {conclusion.confidence}")


async def main():
    scope = ScopeValidator(in_scope_assets=["http://localhost:5001", "http://localhost:5002", "http://localhost:5003", "http://localhost:5004"], out_of_scope_assets=[])
    transport = AiohttpTransport()
    # Simple transport proxy to log requests
    orig_send = transport.send
    async def patched_send(method, url, headers, params, body, timeout, max_response_size):
        print(f"Transport sending {method} {url}")
        if body:
            print(f"Transport body: {body}")
        return await orig_send(method, url, headers, params, body, timeout, max_response_size)
    transport.send = patched_send
    
    re = RequestEngine(scope_validator=scope, transport=transport)
    engine = VulnerabilityExecutionEngine(request_engine=re, scope_validator=scope, allow_loopback=True)
    verification_engine = VerificationEngine()

    # 1. Open Redirect
    hyp_or = VulnerabilityHypothesis(
        hypothesis_id="HYP-OR",
        vulnerability_id="C007",
        check_id="C007_Open_Redirect",
        target="http://localhost:5001",
        endpoint="http://localhost:5001/redirect?url=/",
        parameter="url",
        method="GET",
        account_context="ANONYMOUS",
        baseline_required=True,
        test_strategy="OPEN_REDIRECT_PROBE",
        expected_signal="Redirect",
        safety_level="SAFE",
        request_budget=15,
    )
    await test_target(engine, hyp_or, verification_engine)

    # 2. SSTI
    hyp_ssti = VulnerabilityHypothesis(
        hypothesis_id="HYP-SSTI",
        vulnerability_id="C028",
        check_id="C028_SSTI",
        target="http://localhost:5002",
        endpoint="http://localhost:5002/hello?name=Guest",
        parameter="name",
        method="GET",
        account_context="ANONYMOUS",
        baseline_required=True,
        test_strategy="INSPECTION_PROBE",
        expected_signal="Output",
        safety_level="SAFE",
        request_budget=15,
    )
    await test_target(engine, hyp_ssti, verification_engine)

    # 3. NoSQL Injection
    hyp_nosql = VulnerabilityHypothesis(
        hypothesis_id="HYP-NOSQL",
        vulnerability_id="C025",
        check_id="C025_NoSQL_Injection",
        target="http://localhost:5003",
        endpoint="http://localhost:5003/login",
        parameter="password",
        method="POST",
        account_context="ANONYMOUS",
        baseline_required=True,
        test_strategy="INSPECTION_PROBE",
        expected_signal="Output",
        safety_level="SAFE",
        request_budget=15,
    )
    await test_target(engine, hyp_nosql, verification_engine)
    
    # 4. SSRF
    hyp_ssrf = VulnerabilityHypothesis(
        hypothesis_id="HYP-SSRF",
        vulnerability_id="C036",
        check_id="C036_SSRF_Indicators",
        target="http://localhost:5004",
        endpoint="http://localhost:5004/fetch?url=http://example.com",
        parameter="url",
        method="GET",
        account_context="ANONYMOUS",
        baseline_required=True,
        test_strategy="INSPECTION_PROBE",
        expected_signal="Output",
        safety_level="SAFE",
        request_budget=15,
    )
    await test_target(engine, hyp_ssrf, verification_engine)

if __name__ == "__main__":
    asyncio.run(main())
