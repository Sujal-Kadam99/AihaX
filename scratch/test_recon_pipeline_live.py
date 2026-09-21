import asyncio
import http.server
import json
import os
import socketserver
import sys
import threading
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.models.database import get_db, Scan
from backend.agents.recon_agent import ReconAgent, ReconExecutionConfig, ReconObservationCategory
from backend.execution.tool_execution_boundary import ToolExecutionBoundary

class SimpleTargetHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            self.send_header("X-Powered-By", "PHP/7.4.3")
            self.end_headers()
            html = """
            <!DOCTYPE html>
            <html>
            <head><title>Test Target App</title></head>
            <body>
                <h1>Welcome to Test App</h1>
                <a href="/login.php">Login</a>
                <a href="/vulnerabilities/sqli/">SQL Injection</a>
                <a href="/api/v1/users">API Users</a>
                <a href="/admin/">Admin Dashboard</a>
            </body>
            </html>
            """
            self.wfile.write(html.encode("utf-8"))
        elif self.path in ("/login.php", "/vulnerabilities/sqli/", "/api/v1/users", "/admin/"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(f"Endpoint {self.path} OK".encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        pass

def run_server(port=9876):
    server = socketserver.TCPServer(("127.0.0.1", port), SimpleTargetHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server

async def test_live_recon():
    server = run_server(9876)
    target_url = "http://127.0.0.1:9876"
    print(f"[*] Started local target test server at {target_url}")

    db = next(get_db())
    scan_id = "test-live-recon-001"

    agent = ReconAgent(
        scan_id=scan_id,
        db=db,
        config={
            "target_url": target_url,
            "in_scope_assets": [target_url, "127.0.0.1"],
            "allow_loopback": True,
            "authorization_confirmed": True,
            "timeout_per_tool": 10,
        }
    )

    print("[*] Executing ReconAgent.execute()...")
    attack_surface = await agent.execute()

    print("\n" + "="*60)
    print("RECON AGENT EXECUTION RESULTS:")
    print("="*60)
    print(f"Status: {attack_surface.get('status')}")
    print(f"Domain: {attack_surface.get('domain')}")
    print(f"Discovered Endpoints count: {len(attack_surface.get('endpoints', []))}")
    print(f"Endpoints: {attack_surface.get('endpoints')}")
    print(f"Tech Stack: {attack_surface.get('tech_stack')}")

    snapshot = getattr(agent, "recon_snapshot", None)
    if snapshot:
        print(f"\nTotal Snapshot Observations: {snapshot.observation_count}")
        print("\nTool Results:")
        for tool_name, res in snapshot.tool_results.items():
            status = res.get("execution_status")
            print(f"  - {tool_name:12}: {status}")

    server.shutdown()
    print("\n[*] Test completed successfully.")

if __name__ == "__main__":
    asyncio.run(test_live_recon())
