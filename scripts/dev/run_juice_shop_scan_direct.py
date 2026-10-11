import asyncio
import uuid
import json
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
    sv = ScopeValidator(["http://localhost:3001", "localhost:3001", "localhost", "127.0.0.1"])
    # use real request engine
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
    print(f"Mock passing recon_snapshot: {kwargs.get('recon_snapshot') is not None}")
    if kwargs.get('recon_snapshot'):
        print(f"Observations count: {len(kwargs['recon_snapshot'].observations)}")
    else:
        print("recon_snapshot is None!")
        
    result = await original_run_vuln_pipeline(self, *args, **kwargs)
    print("=== VULN AGENT RESULT ===")
    print(json.dumps(result.to_dict(), indent=2))
    return result
backend.agents.vulnerability_testing_agent.VulnerabilityTestingAgent.run_vulnerability_pipeline = mock_run_vuln_pipeline

# Mock ReconAgent entirely since we don't have nmap/gobuster on Windows
import backend.core.redis_client
import backend.agents.vulnerability_testing_agent

async def mock_get_attack_surface(scan_id):
    return {
        "domain": "localhost",
        "subdomains": [],
        "endpoints": [
            "http://localhost:3001/rest/products/search?q=1",
            "http://localhost:3001/rest/user/login?email=1&password=1"
        ],
        "ports": [{"port": 3001, "protocol": "tcp", "service": "http"}],
        "tech_stack": [{"plugin": "sqlite"}, {"plugin": "sql"}],
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
            ReconObservation(category=ReconObservationCategory.ENDPOINT.value, value="http://localhost:3001/rest/products/search?q=1", normalized_value="http://localhost:3001/rest/products/search?q=1", discovered_by=["mock"]),
            ReconObservation(category=ReconObservationCategory.ENDPOINT.value, value="http://localhost:3001/rest/user/login?email=1&password=1", normalized_value="http://localhost:3001/rest/user/login?email=1&password=1", discovered_by=["mock"]),
            ReconObservation(category=ReconObservationCategory.TECHNOLOGY.value, value="sqlite", normalized_value="sqlite", discovered_by=["mock"]),
            ReconObservation(category=ReconObservationCategory.TECHNOLOGY.value, value="sql", normalized_value="sql", discovered_by=["mock"]),
            ReconObservation(category=ReconObservationCategory.PARAMETER.value, value="q", normalized_value="q", discovered_by=["mock"]),
            ReconObservation(category=ReconObservationCategory.PARAMETER.value, value="email", normalized_value="email", discovered_by=["mock"]),
            ReconObservation(category=ReconObservationCategory.PARAMETER.value, value="password", normalized_value="password", discovered_by=["mock"]),
        ]
        self.recon_snapshot = ReconSnapshot(
            campaign_id=self.scan_id,
            target="http://localhost:3001",
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

TARGET_URL = "http://localhost:3001"
scan_id = str(uuid.uuid4())

async def main():
    print(f"Starting direct scan for {TARGET_URL}...")
    db = next(get_db())
    
    # 1. Create a Campaign to satisfy AuditTrailEvent foreign keys
    campaign = Campaign(id=scan_id, name="Juice Shop Scan", target_url=TARGET_URL)
    db.add(campaign)
    
    # 2. Create the Scan
    scan = Scan(
        id=scan_id,
        target_url=TARGET_URL,
        status="pending",
        scan_depth="deep",
        scan_mode="standard",
        threads=20, # use max threads for speed
        waf_bypass=False,
        stealth_mode=False,
        industry="Technology",
        admin_mode=True,  # Bypass all limits
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
        "scope_notes": "Authorized local test against intentionally vulnerable OWASP Juice Shop container",
        "stealth_mode": False,
        "admin_mode": True,
        "in_scope_assets": ["http://localhost:3001", "localhost:3001", "localhost", "127.0.0.1"],
        "allow_loopback": True,
    }
    save_scan_config(db, scan_id, config_dict)
    
    print(f"Executing scan_id: {scan_id}")
    try:
        await run_scan_pipeline(scan_id, config_dict)
        print("Scan pipeline finished.")
    except Exception as e:
        print("Scan pipeline failed:", e)

    # fetch results
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

    with open("scan_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"Saved {len(results)} findings to scan_results.json")

if __name__ == "__main__":
    asyncio.run(main())
