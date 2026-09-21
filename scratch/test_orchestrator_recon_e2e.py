import asyncio
import http.server
import json
import os
import socketserver
import sys
import threading
import uuid
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.models.database import get_db, Scan, get_session_factory
from backend.persistence.models import Campaign
from backend.services.orchestrator import run_scan_pipeline

class OrchestratorTargetHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Apache/2.4.41")
            self.end_headers()
            html = """
            <!DOCTYPE html>
            <html>
            <body>
                <a href="/login.php">Login</a>
                <a href="/vulnerabilities/sqli/">SQL Injection</a>
                <a href="/api/v1/users">API Users</a>
            </body>
            </html>
            """
            self.wfile.write(html.encode("utf-8"))
        elif self.path in ("/login.php", "/vulnerabilities/sqli/", "/api/v1/users"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        pass

def run_server(port=9877):
    server = socketserver.TCPServer(("127.0.0.1", port), OrchestratorTargetHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server

async def test_full_orchestrator():
    server = run_server(9877)
    target_url = "http://127.0.0.1:9877"
    scan_id = f"orch-test-{uuid.uuid4().hex[:8]}"

    factory = get_session_factory()
    db = factory()
    try:
        camp = Campaign(
            id=scan_id,
            name=f"Test Campaign {scan_id}",
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
            "timeout_per_tool": 5,
        }

        print(f"[*] Running full scan orchestrator pipeline on {target_url} (scan_id={scan_id})...")
        await run_scan_pipeline(scan_id, config)

        db.refresh(scan)
        print("\n" + "="*60)
        print("FULL ORCHESTRATOR SCAN RESULT:")
        print("="*60)
        print(f"Scan status: {scan.status}")
        print(f"Risk score: {scan.risk_score}")
        print(f"Tech stack: {scan.tech_stack}")

    finally:
        db.close()
        server.shutdown()

if __name__ == "__main__":
    asyncio.run(test_full_orchestrator())
