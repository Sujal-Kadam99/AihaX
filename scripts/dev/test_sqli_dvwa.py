import asyncio
import json
from backend.services.request_engine import RequestEngine
from backend.core.scope_validator import ScopeValidator
from backend.services.vulnerability_execution_engine import VulnerabilityExecutionEngine, ExecutionMode
from backend.services.vulnerability_hypothesis_engine import VulnerabilityHypothesis
from backend.agents.auth_agent import SharedAuthContext

async def main():
    scope = ScopeValidator(in_scope_assets=["http://localhost:8080"])
    re = RequestEngine(scope_validator=scope)
    
    # We will log the actual requests and responses by modifying the request engine temporarily or just printing
    
    engine = VulnerabilityExecutionEngine(request_engine=re, scope_validator=scope)
    
    hyp = VulnerabilityHypothesis(
        hypothesis_id="HYP-1",
        vulnerability_id="C023",
        check_id="C023_SQL_Injection",
        target="http://localhost:8080",
        endpoint="http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit",
        parameter="id",
        method="GET",
        account_context="ANONYMOUS",
        baseline_required=True,
        test_strategy="SQLI_DIFFERENTIAL_ERROR",
        expected_signal="Error",
        safety_level="SAFE",
        request_budget=5,
    )
    
    import httpx
    async with httpx.AsyncClient(follow_redirects=True) as client:
        resp = await client.post("http://localhost:8080/login.php", data={"username": "admin", "password": "password", "Login": "Login"})
        cookies = dict(client.cookies)
        cookies["security"] = "low"
        
    class MockAuth:
        def build_request_context(self, account_id=1):
            from backend.agents.auth_agent import AuthenticationContext
            ctx = AuthenticationContext(name="admin", auth_type="cookie")
            ctx.cookies = cookies
            return ctx
            
    engine.shared_auth_context = MockAuth()
    
    print("Running execution engine...")
    evidence = await engine.execute_hypothesis(hyp, mode=ExecutionMode.SIMULATION, shared_auth_context=MockAuth())
    
    print(json.dumps(evidence.__dict__, indent=2))
    
if __name__ == "__main__":
    asyncio.run(main())
