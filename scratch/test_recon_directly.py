import asyncio
import os
import json
from backend.models.database import get_db
import backend.core.scope_validator
import backend.agents.recon_agent
import backend.execution.tool_execution_boundary
from backend.agents.recon_agent import ReconAgent, ReconExecutionConfig

def mock_validate(*args, **kwargs):
    return True, "Mock safe"

backend.core.scope_validator.validate_destination_safety = mock_validate
backend.agents.recon_agent.validate_destination_safety = mock_validate
backend.execution.tool_execution_boundary.validate_destination_safety = mock_validate

async def test_recon():
    db = next(get_db())
    scan_id = "test-recon-scan"
    
    agent = ReconAgent(
        scan_id=scan_id, 
        db=db, 
        config={
            "target_url": "http://localhost:3001",
            "in_scope_assets": ["http://localhost:3001", "localhost", "127.0.0.1"]
        }
    )
    
    cfg = ReconExecutionConfig(
        campaign_id=scan_id,
        target_url="http://localhost:3001",
        in_scope_assets=["http://localhost:3001", "localhost", "127.0.0.1"],
        authorization_confirmed=True,
        execution_mode="AUTHORIZED_LIVE_RECON"
    )
    
    snapshot = await agent.execute_recon_pipeline(cfg, db=db)
    
    print(f"Status: {snapshot.status}")
    print(f"Observations: {len(snapshot.observations)}")
    for t in snapshot.tool_results:
        res = snapshot.tool_results[t]
        if res.get('execution_status') != 'SUCCESS':
            print(f"Tool {t} failed: {res}")
        else:
            print(f"Tool {t} succeeded")

if __name__ == "__main__":
    asyncio.run(test_recon())
