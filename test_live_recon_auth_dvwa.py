import asyncio
import json
import logging
import time
import uuid
from playwright.async_api import async_playwright
from backend.models.database import (
    AgentLog,
    Finding,
    Scan,
    get_session_factory,
    init_db,
)
from backend.persistence.models import (
    Campaign,
    AuditTrailEvent,
    EvidenceRecord,
)
from backend.services.orchestrator import run_scan_pipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

async def setup_dvwa():
    print("Setting up DVWA database & security=low...")
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            
            # Setup DB
            await page.goto("http://localhost:8080/setup.php", timeout=15000)
            btn = page.locator("input[name='create_db'], input[value*='Create'], button:has-text('Create')")
            if await btn.count() > 0:
                await btn.first.click()
                await page.wait_for_timeout(1000)
                
            # Login
            await page.goto("http://localhost:8080/login.php", timeout=15000)
            await page.fill("input[name='username']", "admin")
            await page.fill("input[name='password']", "password")
            await page.click("input[name='Login'], input[type='submit']")
            await page.wait_for_timeout(1000)
            
            # Set security to low
            await page.goto("http://localhost:8080/security.php", timeout=15000)
            sec = page.locator("select[name='security']")
            if await sec.count() > 0:
                await sec.select_option("low")
                await page.click("input[name='seclev_submit'], input[type='submit']")
                await page.wait_for_timeout(500)
                
            print("DVWA setup complete.")
            await browser.close()
    except Exception as e:
        print(f"DVWA setup note: {e}")

async def run():
    await setup_dvwa()
    
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
    
    campaign = Campaign(
        id=scan_id,
        name="DVWA Authenticated Recon Validation",
        target_url="http://localhost:8080",
        mode="SAFE_SCAN",
        assessment_mode="CONTROLLED",
        status="RUNNING",
    )
    db.add(campaign)
    db.commit()
    
    config = {
        "target_url": "http://localhost:8080",
        "authorization_confirmed": True,
        "allow_loopback": True,
        "in_scope_assets": ["http://localhost:8080", "localhost:8080", "localhost", "127.0.0.1:8080", "127.0.0.1"],
        "out_of_scope_assets": [],
        "scan_depth": "deep",
        "scan_mode": "standard",
        "execution_mode": "AUTHORIZED_LIVE_RECON",
        "admin_mode": True,
        "threads": 5,
        "rate_limit_rps": 10,
        "max_concurrency": 5,
        "enable_active_crawler": True,
        "enable_url_discovery": True,
        "enable_directory_discovery": True,
        "enable_tech_detection": True,
        "enable_port_scan": True,
        "timeout_per_tool": 30,
        "primary_creds": {"username": "admin", "password": "password"},
    }
    
    start_t = time.monotonic()
    await run_scan_pipeline(scan_id, config)
    duration = time.monotonic() - start_t
    
    db.expire_all()
    scan_rec = db.query(Scan).filter_by(id=scan_id).first()
    findings = db.query(Finding).filter_by(scan_id=scan_id).all()
    agent_logs = db.query(AgentLog).filter_by(scan_id=scan_id).all()
    audit_events = db.query(AuditTrailEvent).filter_by(campaign_id=scan_id).all()
    
    print("\n" + "="*80)
    print(f"PIPELINE RUN FINISHED (Status: {scan_rec.status}, Duration: {duration:.2f}s)")
    print("="*80)
    
    # Check recon agent logs
    latest_recon_obs = []
    for log in agent_logs:
        if log.agent_id == 1:
            try:
                d = json.loads(log.message)
                if "observations" in d:
                    latest_recon_obs = d["observations"]
            except:
                pass
                
    params_discovered = set()
    endpoints_discovered = set()
    for obs in latest_recon_obs:
        cat = obs.get("category")
        val = obs.get("normalized_value") or obs.get("value")
        if cat == "PARAMETER":
            params_discovered.add(val)
        elif cat in ("ENDPOINT", "DIRECTORY", "HISTORICAL_URL"):
            endpoints_discovered.add(val)
            if "?" in val:
                q = val.split("?", 1)[1]
                for p in q.split("&"):
                    if "=" in p:
                        params_discovered.add(p.split("=")[0])
                        
    print(f"\n[RECON RESULTS]")
    print(f"Total Observations: {len(latest_recon_obs)}")
    print(f"Endpoints Count: {len(endpoints_discovered)}")
    print(f"Parameters Count: {len(params_discovered)}")
    print(f"Parameters Discovered: {sorted(list(params_discovered))}")
    print("\nSample Endpoints:")
    for ep in sorted(list(endpoints_discovered))[:15]:
        print(f"  {ep}")
        
    print("\n[HYPOTHESES & AUDIT EVENTS]")
    hyp_events = [e for e in audit_events if e.event_type in ("HYPOTHESIS_CREATED", "VULNERABILITY_SELECTION_COMPLETED", "VERIFICATION_COMPLETED", "FINDING_CREATED")]
    print(f"Total relevant audit events: {len(hyp_events)}")
    for ev in hyp_events:
        meta = json.loads(ev.metadata_json) if ev.metadata_json else {}
        cid = meta.get("check_id") or ev.object_id or ""
        t_url = meta.get("target_url") or ""
        st = meta.get("status") or ""
        re = meta.get("reason") or ""
        print(f"  [{ev.event_type}] {cid} - target: {t_url} - status: {st} - reason: {re}")

    print("\n[FINDINGS SUMMARY]")
    print(f"Total Findings: {len(findings)}")
    for f in findings:
        print(f"  Finding {f.id}: title='{f.title}', vuln_type='{f.vuln_type}', verdict='{f.verdict}', status='{f.verification_status}', severity='{f.severity}', url='{f.affected_url}', param='{f.affected_param}'")
        
    db.close()

if __name__ == "__main__":
    asyncio.run(run())
