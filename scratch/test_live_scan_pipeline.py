import asyncio
import json
import uuid
from aiohttp import web
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import backend.agents.checks
import backend.persistence.models
from backend.models.database import Base, Finding, Program, ProgramScope, Scan, get_session_factory
from backend.services.orchestrator import run_scan_pipeline, save_scan_config
from backend.tests.fixtures.security_lab.lab_server import create_security_lab_app
import backend.core.scope_validator

async def main():
    # Setup test DB in memory
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    
    # Start in-process security lab
    app = create_security_lab_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 5005)
    await site.start()
    target_url = "http://127.0.0.1:5005"
    print(f"Lab server running at {target_url}")

    # Patch session factory for orchestrator
    import backend.services.orchestrator
    backend.services.orchestrator.get_session_factory = lambda: Session

    db = Session()
    scan_id = f"test-scan-{uuid.uuid4().hex[:8]}"
    campaign = backend.persistence.models.Campaign(id=scan_id, name="Test Scan", target_url=target_url)
    db.add(campaign)
    scan = Scan(
        id=scan_id,
        target_url=target_url,
        status="pending",
        created_at=backend.models.database.get_utc_now()
    )
    db.add(scan)
    db.commit()

    config = {
        "target": target_url,
        "target_url": target_url,
        "scope": [target_url],
        "in_scope_assets": [target_url],
        "allowed_ports": [5005],
        "allow_loopback": True,
        "authorization_confirmed": True,
        "operator_id": "auditor",
        "operator_approval_id": "appr-audit-01",
        "timeout_per_tool": 2,
        "enable_subdomain_discovery": False,
        "enable_port_scan": False,
    }
    save_scan_config(db, scan_id, config)
    db.close()

    print(f"Starting scan pipeline for {scan_id}...")
    errors = []
    try:
        await run_scan_pipeline(scan_id, config)
    except Exception as e:
        errors.append(str(e))
        print(f"Scan pipeline exception: {e}")

    # Query results
    db = Session()
    final_scan = db.query(Scan).filter_by(id=scan_id).first()
    findings = db.query(Finding).filter_by(scan_id=scan_id).all()
    
    status_breakdown = {}
    for f in findings:
        st = f.verification_status or "UNKNOWN"
        status_breakdown[st] = status_breakdown.get(st, 0) + 1

    print("\n=== SCAN EXECUTION SUMMARY ===")
    print(f"Final Scan Status: {final_scan.status if final_scan else 'NOT_FOUND'}")
    print(f"Total Findings Produced: {len(findings)}")
    print(f"Finding Status Breakdown: {status_breakdown}")
    print(f"Pipeline Errors Encountered: {errors}")

    for f in findings:
        print(f" - [{f.check_id or f.vuln_type}] {f.title} | Status: {f.verification_status} | Verdict: {f.verdict} | Severity: {f.severity} | Conf: {f.confidence}")

    await runner.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
