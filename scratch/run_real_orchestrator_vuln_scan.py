import asyncio
import base64
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.models.database import get_db, Scan, Finding, get_session_factory
from backend.persistence.models import Campaign
from backend.services.orchestrator import run_scan_pipeline, save_scan_config

# Import target apps
from scratch.kill_scratch_ports import kill as kill_ports
from scratch.new_5_targets_app import app as vuln_app

def start_vuln_server(port=5005):
    kill_ports([port])
    from werkzeug.serving import make_server
    server = make_server("127.0.0.1", port, vuln_app, threaded=True)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"[*] Started multi-vulnerability test application on http://127.0.0.1:{port}")
    return server

async def run_autonomous_scan():
    port = 5005
    server = start_vuln_server(port)
    target_url = f"http://127.0.0.1:{port}"
    scan_id = f"auto-scan-{uuid.uuid4().hex[:8]}"

    factory = get_session_factory()
    db = factory()
    try:
        camp = Campaign(
            id=scan_id,
            name=f"Autonomous E2E Scan {scan_id}",
            target_url=target_url,
            status="RUNNING",
        )
        scan = Scan(
            id=scan_id,
            target_url=target_url,
            status="pending",
        )
        db.add(camp)
        db.add(scan)
        db.commit()

        config = {
            "target_url": target_url,
            "target": target_url,
            "in_scope_assets": [target_url, "127.0.0.1"],
            "allow_loopback": True,
            "authorization_confirmed": True,
            "execution_mode": "authorized_live",
            "timeout_per_tool": 8,
            "operator_id": "admin",
            "operator_approval_id": "appr-autonomous-e2e",
        }

        print(f"\n[*] Executing 9-Agent Orchestrator Pipeline on {target_url} (scan_id={scan_id})...")
        await run_scan_pipeline(scan_id, config)

        db.refresh(scan)
        print("\n" + "="*70)
        print("AUTONOMOUS SCAN EXECUTION RESULTS")
        print("="*70)
        print(f"Final Scan Status: {scan.status}")
        print(f"Final Risk Score : {scan.risk_score}")

        findings = db.query(Finding).filter_by(scan_id=scan_id).all()
        print(f"\n--- Total Findings Stored: {len(findings)} ---")
        for f in findings:
            print(f"  - [{f.severity}] {f.title} ({f.vuln_type})")
            print(f"    Affected URL: {f.affected_url}")
            print(f"    Verdict     : {f.verdict}")
            print(f"    Status      : {f.verification_status}")
            print(f"    Confidence  : {f.confidence}%")
            print(f"    False Pos   : {f.false_positive}")
            print()

    finally:
        db.close()
        server.shutdown()
        kill_ports([port])

if __name__ == "__main__":
    asyncio.run(run_autonomous_scan())
