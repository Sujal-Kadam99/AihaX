import asyncio
import json
import httpx
from bs4 import BeautifulSoup
from backend.services.request_engine import RequestEngine, AiohttpTransport
from backend.core.scope_validator import ScopeValidator
from backend.services.vulnerability_execution_engine import VulnerabilityExecutionEngine, ExecutionMode
from backend.services.vulnerability_hypothesis_engine import VulnerabilityHypothesis
from backend.models.database import Finding
from backend.services.verification_engine import VerificationEngine, VerificationContext, VerificationBudget, VerificationRegistry
from backend.services.verification_strategies.sql_injection_strategy import SqlInjectionVerificationStrategy
from backend.services.verification_strategies.blind_sql_injection_strategy import BlindSqlInjectionVerificationStrategy

VerificationRegistry.register(SqlInjectionVerificationStrategy)
VerificationRegistry.register(BlindSqlInjectionVerificationStrategy)

async def setup_dvwa(client: httpx.AsyncClient):
    resp = await client.get("http://localhost:8080/login.php")
    soup = BeautifulSoup(resp.text, 'html.parser')
    token_input = soup.find('input', {'name': 'user_token'})
    if not token_input:
        return False, None
    user_token = token_input.get('value')
    
    login_data = {
        'username': 'admin',
        'password': 'password',
        'Login': 'Login',
        'user_token': user_token
    }
    resp = await client.post("http://localhost:8080/login.php", data=login_data, follow_redirects=False)
    if resp.status_code != 302:
        return False, None
        
    client.cookies.delete('security', domain='localhost')
    client.cookies.delete('security', domain='127.0.0.1')
    client.cookies.set('security', 'low', domain='localhost')
    
    resp = await client.get("http://localhost:8080/setup.php")
    soup = BeautifulSoup(resp.text, 'html.parser')
    token_input = soup.find('input', {'name': 'user_token'})
    if not token_input:
        return False, None
    user_token = token_input.get('value')
    
    setup_data = {
        'create_db': 'Create / Reset Database',
        'user_token': user_token
    }
    resp = await client.post("http://localhost:8080/setup.php", data=setup_data, follow_redirects=False)
    
    # Avoid httpx CookieConflict by getting them directly
    cookie_dict = {}
    for c in client.cookies.jar:
        cookie_dict[c.name] = c.value
    
    return True, cookie_dict

async def test_hypothesis(engine, hyp, cookies):
    class MockAuth:
        def build_request_context(self, account_id=1):
            from backend.services.request_engine import AuthenticationContext
            ctx = AuthenticationContext(name="admin", auth_type="cookie")
            ctx.cookies = cookies
            return ctx

    print(f"\n--- Testing {hyp.check_id} ---")
    print("Running execution engine...")
    evidence = await engine.execute_hypothesis(hyp, mode=ExecutionMode.SIMULATION, shared_auth_context=MockAuth())
    
    print(f"Execution Engine Result: {evidence.result_status}")
    if evidence.response_metadata.get('body'):
        body_snippet = evidence.response_metadata['body'][:500]
        if "root:x:0:0" in evidence.response_metadata['body']:
            print("=> SUCCESS: 'root:x:0:0' found in captured execution evidence body!")
        print(f"Body snippet captured: {body_snippet!r}...")
        
    if evidence.result_status not in ["DETECTED", "EXPLOITABLE"]:
        print("Not detected, skipping verification.")
        print(f"Evidence details: {vars(evidence)}")
        return
        
    proof_req = f"{evidence.request_metadata.get('method')} {evidence.request_metadata.get('endpoint')}\n"
    for k, v in evidence.request_metadata.get('headers', {}).items():
        proof_req += f"{k}: {v}\n"
    if evidence.request_metadata.get('body'):
        body = evidence.request_metadata.get('body')
        proof_req += f"\n{body if isinstance(body, str) else json.dumps(body)}"

    # Convert evidence to Finding
    finding = Finding(
        id="find-123",
        scan_id="scan-123",
        agent_id=1,
        title=f"{hyp.check_id} Detected",
        vuln_type=hyp.vulnerability_id,
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
    # Pack raw evidence from execution into finding dict as expected by VerifyAgent
    finding.candidate_evidence = {
        "proof_request": proof_req,
        "proof_response": evidence.response_metadata.get('body', str(evidence.response_metadata)),
        "payload": evidence.request_metadata.get('payload', ''),
        "location": hyp.parameter, # approximation
        "baseline_latency": 0,
        "tech_stack": ["mysql", "php"]
    }
    
    print("Running verification engine...")
    verify_engine = VerificationEngine()
    re = engine.request_engine
    conclusion = await verify_engine.verify_finding(
        finding=finding,
        request_engine=re,
        authorization_confirmed=True
    )
    
    print(f"Verification Engine Result: {conclusion.status.name}")
    print(f"Reason: {conclusion.reason_code}")
    print(f"Description: {conclusion.reason_description}")
    print(f"Confidence: {conclusion.confidence}")
    if conclusion.request_ids:
        print(f"Requests made: {len(conclusion.request_ids)}")

async def main():
    async with httpx.AsyncClient(follow_redirects=True) as client:
        success, cookies = await setup_dvwa(client)
        if not success:
            print("Failed to authenticate to DVWA.")
            return
            
    print(f"Authenticated successfully. Cookies: {cookies}")
    
    async with httpx.AsyncClient(follow_redirects=False, cookies=cookies) as c:
        resp = await c.get("http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit")
        print(f"Manual check: status={resp.status_code}")
        if resp.status_code == 302:
            print(f"Manual check redirected to: {resp.headers.get('Location')}")
    
    # Patch AiohttpTransport to print what it sends
    orig_send = AiohttpTransport.send
    async def patched_send(self, method, url, headers, params, body, timeout, max_response_size):
        if "Cookie" not in headers:
            headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        print(f"Transport sending {method} {url}")
        print(f"Transport headers: {headers}")
        return await orig_send(self, method, url, headers, params, body, timeout, max_response_size)
    AiohttpTransport.send = patched_send
    
    scope = ScopeValidator(in_scope_assets=["http://localhost:8080", "127.0.0.1", "localhost"], out_of_scope_assets=[])
    re = RequestEngine(scope_validator=scope, transport=AiohttpTransport())
    engine = VulnerabilityExecutionEngine(request_engine=re, scope_validator=scope, allow_loopback=True)
    
    # 1. SQLi
    hyp_sqli = VulnerabilityHypothesis(
        hypothesis_id="HYP-1",
        vulnerability_id="C023",
        check_id="C023_SQL_Injection",
        target="http://localhost:8080",
        endpoint="http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit",
        parameter="id",
        method="GET",
        account_context="ACCOUNT_1",
        baseline_required=True,
        test_strategy="SQLI_DIFFERENTIAL_ERROR",
        expected_signal="Error",
        safety_level="SAFE",
        request_budget=15,
    )
    await test_hypothesis(engine, hyp_sqli, cookies)
    
    # 2. Path Traversal
    hyp_pt = VulnerabilityHypothesis(
        hypothesis_id="HYP-2",
        vulnerability_id="C027",
        check_id="C027_Path_Traversal",
        target="http://localhost:8080",
        endpoint="http://localhost:8080/vulnerabilities/fi/?page=include.php",
        parameter="page",
        method="GET",
        account_context="ACCOUNT_1",
        baseline_required=True,
        test_strategy="PATH_TRAVERSAL_PROBE",
        expected_signal="LFI",
        safety_level="SAFE",
        request_budget=15,
    )
    await test_hypothesis(engine, hyp_pt, cookies)
    
    # 3. Command Injection
    hyp_ci = VulnerabilityHypothesis(
        hypothesis_id="HYP-3",
        vulnerability_id="C026",
        check_id="C027_OS_Command_Injection",
        target="http://localhost:8080",
        endpoint="http://localhost:8080/vulnerabilities/exec/",
        parameter="ip",
        method="POST",
        account_context="ACCOUNT_1",
        baseline_required=True,
        test_strategy="COMMAND_INJECTION_PROBE",
        expected_signal="COMMAND_OUTPUT",
        safety_level="SAFE",
        request_budget=15,
    )
    await test_hypothesis(engine, hyp_ci, cookies)

if __name__ == "__main__":
    asyncio.run(main())
