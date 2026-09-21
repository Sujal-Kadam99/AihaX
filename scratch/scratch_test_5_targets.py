import asyncio
import json
import base64
from datetime import datetime, timezone
import sys
sys.path.insert(0, ".")

# Auto-clean port 5005 before anything else
from scratch.kill_scratch_ports import kill as kill_ports
kill_ports([5005])

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
    scope = ScopeValidator(in_scope_assets=["http://localhost:5005"], out_of_scope_assets=[])
    transport = AiohttpTransport()
    
    orig_send = transport.send
    async def patched_send(method, url, headers, params, body, timeout, max_response_size):
        # Allow None body without failing type checks if necessary
        return await orig_send(method, url, headers, params, body, timeout, max_response_size)
    transport.send = patched_send
    
    req_engine = RequestEngine(scope_validator=scope, transport=transport)
    engine = VulnerabilityExecutionEngine(request_engine=req_engine, scope_validator=scope, allow_loopback=True)
    verification_engine = VerificationEngine()

    # 1. CSRF (C016_Missing_SameSite_Cookie)
    print("\n--- Testing C016_Missing_SameSite_Cookie against http://localhost:5005/transfer ---")
    finding_csrf = Finding(
        id="find-C016", scan_id="scan-123", agent_id=1,
        title="C016 Detected", vuln_type="C016_Missing_SameSite_Cookie", category="Injection", severity="High", confidence=90,
        affected_url="http://localhost:5005/transfer", affected_param="", payload="",
        proof_request="POST http://localhost:5005/transfer\nContent-Type: application/x-www-form-urlencoded\nX-CSRF-Token: dummy\n\namount=100&to_account=hacker",
        proof_response='{"status_code": 200}', false_positive=False,
    )
    conclusion_csrf = await verification_engine.verify_finding(finding_csrf, req_engine, True)
    print(f"Verification Engine Result: {conclusion_csrf.status.value}\nReason: {conclusion_csrf.reason_code}\nDescription: {conclusion_csrf.reason_description}")

    # 2. CORS (C004_CORS_Misconfiguration)
    print("\n--- Testing C004_CORS_Misconfiguration against http://localhost:5005/api/data ---")
    finding_cors = Finding(
        id="find-C004", scan_id="scan-123", agent_id=1,
        title="C004 Detected", vuln_type="C004_CORS_Misconfiguration", category="Injection", severity="High", confidence=90,
        affected_url="http://localhost:5005/api/data", affected_param="", payload="",
        proof_request="GET http://localhost:5005/api/data\nOrigin: https://evil.com\n",
        proof_response='{"status_code": 200}', false_positive=False,
    )
    conclusion_cors = await verification_engine.verify_finding(finding_cors, req_engine, True)
    print(f"Verification Engine Result: {conclusion_cors.status.value}\nReason: {conclusion_cors.reason_code}\nDescription: {conclusion_cors.reason_description}")

    # 3. JWT (C020_JWT_Algorithm_Weakness)
    print("\n--- Testing C020_JWT_Algorithm_Weakness against http://localhost:5005/admin ---")
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"role": "user"}).encode()).decode().rstrip("=")
    token = f"{header}.{payload}."
    finding_jwt = Finding(
        id="find-C020", scan_id="scan-123", agent_id=1,
        title="C020 Detected", vuln_type="C020_JWT_Algorithm_Weakness", category="Injection", severity="High", confidence=90,
        affected_url="http://localhost:5005/admin", affected_param="", payload=token,
        proof_request=f"GET http://localhost:5005/admin\nAuthorization: Bearer {token}\n",
        proof_response='{"status_code": 403}', false_positive=False,
    )
    conclusion_jwt = await verification_engine.verify_finding(finding_jwt, req_engine, True)
    print(f"Verification Engine Result: {conclusion_jwt.status.value}\nReason: {conclusion_jwt.reason_code}\nDescription: {conclusion_jwt.reason_description}")

    # 4. File Upload (C055_Dangerous_File_Upload)
    print("\n--- Testing C055_Dangerous_File_Upload against http://localhost:5005/upload ---")
    finding_upload = Finding(
        id="find-C055", scan_id="scan-123", agent_id=1,
        title="C055 Detected", vuln_type="C055_Dangerous_File_Upload", category="Injection", severity="High", confidence=90,
        affected_url="http://localhost:5005/upload", affected_param="file", payload="aihax_upload_harmless_canary_test.php",
        proof_request=f"POST http://localhost:5005/upload\nContent-Type: multipart/form-data; boundary=----WebKitFormBoundary\n\n------WebKitFormBoundary\nContent-Disposition: form-data; name=\"file\"; filename=\"aihax_upload_harmless_canary_test.php\"\nContent-Type: application/x-php\n\n<?php echo 'harmless'; ?>\n------WebKitFormBoundary--\n",
        proof_response='{"status": "success", "url": "/uploads/aihax_upload_harmless_canary_test.php"}', false_positive=False,
    )
    conclusion_upload = await verification_engine.verify_finding(finding_upload, req_engine, True)
    print(f"Verification Engine Result: {conclusion_upload.status.value}\nReason: {conclusion_upload.reason_code}\nDescription: {conclusion_upload.reason_description}")

    # 5. XXE (C033_XXE_Indicators)
    print("\n--- Testing C033_XXE_Indicators against http://localhost:5005/parse-xml ---")
    finding_xxe = Finding(
        id="find-C033", scan_id="scan-123", agent_id=1,
        title="C033 Detected", vuln_type="C033_XXE_Indicators", category="Injection", severity="High", confidence=90,
        affected_url="http://localhost:5005/parse-xml", affected_param="body", payload="",
        proof_request="POST http://localhost:5005/parse-xml\nContent-Type: application/xml\n\n<root>test</root>",
        proof_response='{"status_code": 200}', false_positive=False,
    )
    
    from backend.services.verification_strategies.request_builder import build_injected_request
    import re as regex
    injected_req_xxe = build_injected_request({"affected_url": "http://localhost:5005/parse-xml", "affected_param": "body", "proof_request": finding_xxe.proof_request}, "")
    new_data = regex.sub(r'(<[a-zA-Z0-9_:-]+>)[^<]+(</[a-zA-Z0-9_:-]+>)', r'\1&xxe;\2', injected_req_xxe.body, count=1)
    xxe_payload = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    if "<?xml" in new_data:
        new_data = regex.sub(r'<\?xml[^>]+\?>', xxe_payload, new_data, count=1)
    else:
        new_data = xxe_payload + new_data
    print("XXE INJECTED BODY:\n", new_data)

    conclusion_xxe = await verification_engine.verify_finding(finding_xxe, req_engine, True)
    print(f"Verification Engine Result: {conclusion_xxe.status.value}\nReason: {conclusion_xxe.reason_code}\nDescription: {conclusion_xxe.reason_description}")

if __name__ == "__main__":
    asyncio.run(main())
