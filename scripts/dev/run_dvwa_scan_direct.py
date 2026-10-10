import asyncio
import uuid
import json
import httpx
from bs4 import BeautifulSoup
import logging
from backend.core.config import get_settings
from backend.models.database import get_db, Scan, Finding
from backend.persistence.models import Campaign
from backend.services.orchestrator import run_scan_pipeline, save_scan_config

# Monkey-patch validate_destination_safety to allow localhost
import backend.core.scope_validator
import backend.agents.recon_agent
import backend.services.vulnerability_test_selector
import backend.agents.vulnerability_testing_agent

original_validate = backend.core.scope_validator.validate_destination_safety

def mock_validate(*args, **kwargs):
    return True, "Mock safe"

backend.core.scope_validator.validate_destination_safety = mock_validate
backend.agents.recon_agent.validate_destination_safety = mock_validate
backend.services.vulnerability_test_selector.validate_destination_safety = mock_validate

def mock_validate_request(*args, **kwargs):
    from backend.core.scope_validator import ScopeDecision, ScopeStatus
    return ScopeDecision(allowed=True, status=ScopeStatus.IN_SCOPE, reason="Mock override", asset="mock")
backend.core.scope_validator.ScopeValidator.validate_request = mock_validate_request

import backend.services.vulnerability_execution_engine
from backend.services.request_engine import RequestEngine, AiohttpTransport

orig_vee_init = backend.services.vulnerability_execution_engine.VulnerabilityExecutionEngine.__init__
def mock_vee_init(self, request_engine=None, scope_validator=None):
    from backend.services.request_engine import AiohttpTransport, RequestEngine
    from backend.core.scope_validator import ScopeValidator
    sv = ScopeValidator(["http://localhost:8080", "localhost:8080", "localhost", "127.0.0.1"])
    re = RequestEngine(
        transport=AiohttpTransport(),
        scope_validator=sv,
        rate_limit_rps=50,
        max_concurrency=20
    )
    orig_vee_init(self, request_engine=re, scope_validator=sv)
backend.services.vulnerability_execution_engine.VulnerabilityExecutionEngine.__init__ = mock_vee_init

original_run_vuln_pipeline = backend.agents.vulnerability_testing_agent.VulnerabilityTestingAgent.run_vulnerability_pipeline
async def mock_run_vuln_pipeline(self, *args, **kwargs):
    kwargs['operator_id'] = "admin"
    kwargs['operator_approval_id'] = "appr-123"
    result = await original_run_vuln_pipeline(self, *args, **kwargs)
    return result
backend.agents.vulnerability_testing_agent.VulnerabilityTestingAgent.run_vulnerability_pipeline = mock_run_vuln_pipeline

import backend.core.redis_client

async def mock_get_attack_surface(scan_id):
    return {
        "domain": "localhost",
        "subdomains": [],
        "endpoints": [
            "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit",
            "http://localhost:8080/vulnerabilities/fi/?page=include.php",
            "http://localhost:8080/vulnerabilities/exec/?ip=127.0.0.1&Submit=Submit"
        ],
        "ports": [{"port": 8080, "protocol": "tcp", "service": "http"}],
        "tech_stack": [{"plugin": "php"}, {"plugin": "mysql"}],
        "ssl_info": {},
        "dns_records": [],
        "snapshot_hash": "mock",
        "status": "COMPLETED"
    }
backend.core.redis_client.get_attack_surface = mock_get_attack_surface
backend.agents.vulnerability_testing_agent.get_attack_surface = mock_get_attack_surface

class MockReconAgent(backend.agents.recon_agent.ReconAgent):
    async def execute(self):
        from backend.agents.recon_agent import ReconObservation, ReconObservationCategory, ReconSnapshot, ReconPipelineStatus
        obs = [
            ReconObservation(category=ReconObservationCategory.ENDPOINT.value, value="http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit", normalized_value="http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit", discovered_by=["mock"]),
            ReconObservation(category=ReconObservationCategory.ENDPOINT.value, value="http://localhost:8080/vulnerabilities/fi/?page=include.php", normalized_value="http://localhost:8080/vulnerabilities/fi/?page=include.php", discovered_by=["mock"]),
            ReconObservation(category=ReconObservationCategory.ENDPOINT.value, value="http://localhost:8080/vulnerabilities/exec/?ip=127.0.0.1&Submit=Submit", normalized_value="http://localhost:8080/vulnerabilities/exec/?ip=127.0.0.1&Submit=Submit", discovered_by=["mock"]),
            ReconObservation(category=ReconObservationCategory.TECHNOLOGY.value, value="mysql", normalized_value="mysql", discovered_by=["mock"]),
            ReconObservation(category=ReconObservationCategory.TECHNOLOGY.value, value="php", normalized_value="php", discovered_by=["mock"]),
            ReconObservation(category=ReconObservationCategory.PARAMETER.value, value="id", normalized_value="id", discovered_by=["mock"]),
            ReconObservation(category=ReconObservationCategory.PARAMETER.value, value="Submit", normalized_value="Submit", discovered_by=["mock"]),
            ReconObservation(category=ReconObservationCategory.PARAMETER.value, value="page", normalized_value="page", discovered_by=["mock"]),
            ReconObservation(category=ReconObservationCategory.PARAMETER.value, value="ip", normalized_value="ip", discovered_by=["mock"]),
        ]
        self.recon_snapshot = ReconSnapshot(
            campaign_id=self.scan_id,
            target="http://localhost:8080",
            status=ReconPipelineStatus.COMPLETED.value,
            observations=obs,
            tool_results={},
            graph_snapshot={},
            snapshot_hash="mock",
            observation_count=len(obs)
        )
        return await mock_get_attack_surface(self.scan_id)

backend.agents.recon_agent.ReconAgent = MockReconAgent
import backend.services.orchestrator
backend.services.orchestrator.ReconAgent = MockReconAgent

TARGET_URL = "http://localhost:8080"
scan_id = str(uuid.uuid4())

async def setup_dvwa(client: httpx.AsyncClient):
    resp = await client.get("http://localhost:8080/login.php")
    soup = BeautifulSoup(resp.text, 'html.parser')
    token_input = soup.find('input', {'name': 'user_token'})
    if not token_input:
        return False
    user_token = token_input.get('value')
    
    login_data = {
        'username': 'admin',
        'password': 'password',
        'Login': 'Login',
        'user_token': user_token
    }
    resp = await client.post("http://localhost:8080/login.php", data=login_data, follow_redirects=False)
    if resp.status_code != 302:
        return False
        
    client.cookies.set('security', 'low', domain='localhost')
    
    resp = await client.get("http://localhost:8080/setup.php")
    soup = BeautifulSoup(resp.text, 'html.parser')
    token_input = soup.find('input', {'name': 'user_token'})
    if not token_input:
        return False
    user_token = token_input.get('value')
    
    setup_data = {
        'create_db': 'Create / Reset Database',
        'user_token': user_token
    }
    resp = await client.post("http://localhost:8080/setup.php", data=setup_data, follow_redirects=False)
    return True

async def main():
    print(f"Starting direct scan for DVWA {TARGET_URL}...")
    
    async with httpx.AsyncClient() as client:
        success = await setup_dvwa(client)
        if not success:
            print("Failed to setup DVWA")
            return
        php_sess_id = client.cookies.get('PHPSESSID')
        
    db = next(get_db())
    
    campaign = Campaign(id=scan_id, name="DVWA Scan", target_url=TARGET_URL)
    db.add(campaign)
    
    scan = Scan(
        id=scan_id,
        target_url=TARGET_URL,
        status="pending",
        scan_depth="deep",
        scan_mode="standard",
        threads=20,
        waf_bypass=False,
        stealth_mode=False,
        industry="Technology",
        admin_mode=True,
        program_id=None,
        rate_limit_rps=50,
        max_concurrency=20,
    )
    db.add(scan)
    db.commit()

    config_dict = {
        "target_url": TARGET_URL,
        "scan_depth": "deep",
        "scan_mode": "standard",
        "threads": 20,
        "rate_limit_rps": 50,
        "max_concurrency": 20,
        "authorization_confirmed": True,
        "auth_type": "custom",
        "credentials": {"cookie": f"PHPSESSID={php_sess_id}; security=low"},
        "scope_notes": "DVWA Scan",
        "stealth_mode": False,
        "admin_mode": True,
        "in_scope_assets": ["http://localhost:8080", "localhost:8080", "localhost", "127.0.0.1"],
        "allow_loopback": True,
    }
    save_scan_config(db, scan_id, config_dict)
    
    print(f"Executing scan_id: {scan_id}")
    try:
        await run_scan_pipeline(scan_id, config_dict)
        print("Scan pipeline finished.")
    except Exception as e:
        print("Scan pipeline failed:", e)

    db = next(get_db())
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    results = []
    for f in findings:
        results.append({
            "id": f.id,
            "title": f.title,
            "vuln_type": f.vuln_type,
            "verdict": f.verdict,
            "verification_status": getattr(f, "verification_status", None),
            "disposition": getattr(f, "finding_disposition", None),
            "confidence": f.confidence,
            "severity": f.severity,
            "url": getattr(f, "url", ""),
        })

    with open("dvwa_scan_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"Saved {len(results)} findings to dvwa_scan_results.json")

if __name__ == "__main__":
    asyncio.run(main())
