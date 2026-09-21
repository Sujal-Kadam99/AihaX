import asyncio
import json
import logging
import uuid
from backend.agents.auth_agent import AuthAgent
from backend.agents.recon_agent import ReconAgent
from backend.models.database import init_db, get_session_factory, Scan

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

async def test_auth_and_recon():
    init_db()
    factory = get_session_factory()
    db = factory()
    
    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        target_url="http://localhost:8080",
        status="pending",
        scan_depth="deep",
        scan_mode="standard",
        threads=5,
        admin_mode=True,
        waf_bypass=False,
        stealth_mode=False,
        rate_limit_rps=10,
        max_concurrency=5,
        user_email="operator@aihax.local",
    )
    db.add(scan)
    db.commit()
    
    config = {
        "target_url": "http://localhost:8080",
        "authorization_confirmed": True,
        "allow_loopback": True,
        "in_scope_assets": ["http://localhost:8080"],
        "out_of_scope_assets": [],
        "scan_depth": "deep",
        "scan_mode": "standard",
        "execution_mode": "AUTHORIZED_LIVE_RECON",
        "primary_creds": {"username": "admin", "password": "password"},
    }
    
    # 1. Run ReconAgent (initial)
    recon = ReconAgent(scan_id, db, config)
    await recon.run()
    print("Initial Recon Obs Count:", len(recon.recon_snapshot.observations) if recon.recon_snapshot else 0)
    
    # 2. Run AuthAgent
    auth = AuthAgent(scan_id, db, config)
    res = await auth.run()
    print("Auth Agent Result:", res)
    shared_ctx = getattr(auth, "shared_context", None)
    print("Shared Context:", shared_ctx)
    if shared_ctx:
        print("Account 1 Authenticated:", shared_ctx.account_1_authenticated)
        ctx1 = shared_ctx.account_contexts.get(1)
        if ctx1:
            print("Account 1 Cookies:", ctx1._cookies)
            print("Account 1 Headers:", ctx1._headers)
            print("Account 1 Auth Status:", ctx1.auth_status)
            
    # 3. Run Authenticated Recon Pass
    if shared_ctx:
        updated_snap = await recon.run_authenticated_pass(shared_ctx, db)
        print("Updated Recon Obs Count:", len(updated_snap.observations) if updated_snap else 0)
        if updated_snap:
            for obs in updated_snap.observations:
                print(f"  - [{obs.category}] {obs.normalized_value} ({obs.discovered_by})")
                
    db.close()

if __name__ == "__main__":
    asyncio.run(test_auth_and_recon())
