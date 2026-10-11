import asyncio
import logging
from bs4 import BeautifulSoup
import httpx
from urllib.parse import urlparse

from backend.models.vulnerability import VulnerabilityHypothesis
from backend.services.vulnerability_execution_engine import (
    VulnerabilityExecutionEngine,
    ExecutionMode,
)
from backend.services.request_engine import (
    RequestEngine,
    RequestSpec,
    AuthContext,
    AuthType,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def setup_dvwa(client: httpx.AsyncClient):
    # Get login page to extract token
    resp = await client.get("http://localhost:8080/login.php")
    soup = BeautifulSoup(resp.text, 'html.parser')
    token_input = soup.find('input', {'name': 'user_token'})
    if not token_input:
        logger.error("Could not find user_token on login page")
        return False
    user_token = token_input.get('value')
    
    # Login
    login_data = {
        'username': 'admin',
        'password': 'password',
        'Login': 'Login',
        'user_token': user_token
    }
    resp = await client.post("http://localhost:8080/login.php", data=login_data, allow_redirects=False)
    if resp.status_code != 302:
        logger.error(f"Login failed, expected 302, got {resp.status_code}")
        return False
        
    # Set security to low
    client.cookies.set('security', 'low', domain='localhost')
    
    # Setup database
    resp = await client.get("http://localhost:8080/setup.php")
    soup = BeautifulSoup(resp.text, 'html.parser')
    token_input = soup.find('input', {'name': 'user_token'})
    if not token_input:
        logger.error("Could not find user_token on setup page")
        return False
    user_token = token_input.get('value')
    
    setup_data = {
        'create_db': 'Create / Reset Database',
        'user_token': user_token
    }
    resp = await client.post("http://localhost:8080/setup.php", data=setup_data, allow_redirects=False)
    logger.info(f"Database setup complete (status {resp.status_code})")
    return True

async def run_scan():
    async with httpx.AsyncClient() as client:
        success = await setup_dvwa(client)
        if not success:
            logger.error("Failed to setup DVWA")
            return
            
        php_sess_id = client.cookies.get('PHPSESSID')
        
    engine = VulnerabilityExecutionEngine()
    
    auth_ctx = AuthContext(
        auth_type=AuthType.CUSTOM,
        credentials={"cookie": f"PHPSESSID={php_sess_id}; security=low"}
    )
    
    hypotheses = [
        VulnerabilityHypothesis(
            hypothesis_id="HYP-DVWA-SQLI",
            vulnerability_id="C023",
            check_id="C023",
            target="http://localhost:8080",
            endpoint="http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit",
            parameter="id",
            method="GET",
            account_context="DVWA_ADMIN",
            baseline_required=True,
            test_strategy="SQLI_DIFFERENTIAL_ERROR",
            expected_signal="Error or Anomaly",
            safety_level="SAFE",
            request_budget=3,
        ),
        VulnerabilityHypothesis(
            hypothesis_id="HYP-DVWA-PT",
            vulnerability_id="C031",
            check_id="C031",
            target="http://localhost:8080",
            endpoint="http://localhost:8080/vulnerabilities/fi/?page=include.php",
            parameter="page",
            method="GET",
            account_context="DVWA_ADMIN",
            baseline_required=True,
            test_strategy="PATH_TRAVERSAL_PROBE",
            expected_signal="File Content",
            safety_level="SAFE",
            request_budget=2,
        ),
    ]
    
    for h in hypotheses:
        logger.info(f"Executing {h.hypothesis_id} - {h.test_strategy}")
        # HACK: Mock authorization to let engine run
        # Wait, the engine checks authorization by default via execution_engine...
        # Wait, the hypotheses need to be evaluated via _evaluate_differential.
        # But execute_hypothesis runs the network calls! It needs auth_ctx mapped.
        # The engine uses the auth_ctx in RequestSpec. However, VulnerabilityExecutionEngine gets the auth context
        # from auth_state or uses the hypothesis.auth_context.
        # Since I'm using ExecutionMode.SIMULATION, wait, SIMULATION mode uses MockTransport if I have one, but I didn't inject one!
        # If I use ExecutionMode.AUTHORIZED_LIVE, it requires approval!
        pass # Will fix mode

if __name__ == "__main__":
    asyncio.run(run_scan())
