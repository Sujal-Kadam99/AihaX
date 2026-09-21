import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.models.database import get_session_factory, Scan, Finding
from backend.persistence.models import Campaign
from backend.services.orchestrator import run_scan_pipeline
from backend.agents.recon_agent import ReconAgent, ReconExecutionConfig
from backend.services.vulnerability_test_selector import VulnerabilityTestSelector
from backend.services.vulnerability_hypothesis_engine import VulnerabilityHypothesisEngine
from backend.services.vulnerability_execution_engine import VulnerabilityExecutionEngine, ExecutionMode
from backend.services.request_engine import RequestEngine, AiohttpTransport
from backend.core.scope_validator import ScopeValidator
from scratch.kill_scratch_ports import kill as kill_ports
from scratch.new_5_targets_app import app as vuln_app
from werkzeug.serving import make_server
import threading

def start_vuln_server(port=5005):
    kill_ports([port])
    server = make_server("127.0.0.1", port, vuln_app, threaded=True)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server

async def trace_pipeline():
    port = 5005
    server = start_vuln_server(port)
    target_url = f"http://127.0.0.1:{port}"
    scan_id = "trace-scan-1"

    factory = get_session_factory()
    db = factory()
    try:
        cfg = ReconExecutionConfig(
            campaign_id=scan_id,
            target_url=target_url,
            authorization_confirmed=True,
            in_scope_assets=[target_url, "127.0.0.1"],
            allow_loopback=True,
            execution_mode="AUTHORIZED_LIVE_RECON",
            timeout_per_tool=8,
        )
        recon = ReconAgent(scan_id, db, {
            "target_url": target_url,
            "authorization_confirmed": True,
            "in_scope_assets": [target_url, "127.0.0.1"],
            "allow_loopback": True,
            "execution_mode": "AUTHORIZED_LIVE_RECON",
            "timeout_per_tool": 8,
        })
        print("\n[1] Running ReconAgent...")
        attack_surface = await recon.execute()
        snapshot = recon.recon_snapshot
        print(f"Recon completed. Snapshot observations: {len(snapshot.observations) if snapshot else 0}")
        print(f"Attack surface endpoints: {attack_surface.get('endpoints', [])}")
        for obs in (snapshot.observations if snapshot else []):
            print(f"  Obs: {obs.category} -> {obs.normalized_value}")

        print("\n[2] Running VulnerabilityTestSelector...")
        selector = VulnerabilityTestSelector()
        matrix = selector.select_tests(
            target_url=target_url,
            recon_snapshot=snapshot,
            authorization_confirmed=True,
            in_scope_assets=[target_url, "127.0.0.1"],
            allow_loopback=True,
        )
        print(f"Total Registered: {matrix.total_registered}")
        print(f"Applicable: {matrix.applicable_count}")
        print(f"Blocked: {matrix.blocked_count}")
        print(f"Prereq Missing: {matrix.prerequisite_missing_count}")
        print(f"Not Applicable: {matrix.not_applicable_count}")
        
        applicable_entries = [e for e in matrix.entries if e.applicability.startswith("APPLICABLE_")]
        print(f"\nApplicable Check Entries ({len(applicable_entries)}):")
        for e in applicable_entries:
            print(f"  - {e.check_id} ({e.vulnerability_id}): priority={e.priority}, endpoints={e.recommended_targets}")

        print("\n[3] Running VulnerabilityHypothesisEngine...")
        hypo_engine = VulnerabilityHypothesisEngine()
        hypotheses = hypo_engine.generate_hypotheses(matrix, campaign_id=scan_id)
        print(f"Generated Hypotheses: {len(hypotheses)}")
        for h in hypotheses[:10]:
            print(f"  - Hypothesis {h.hypothesis_id}: check={h.check_id}, endpoint={h.endpoint}, method={h.method}")

        print("\n[4] Running VulnerabilityExecutionEngine on Hypotheses...")
        scope_val = ScopeValidator(in_scope_assets=[target_url, "127.0.0.1"])
        re = RequestEngine(scope_validator=scope_val, transport=AiohttpTransport())
        exec_engine = VulnerabilityExecutionEngine(request_engine=re, scope_validator=scope_val, allow_loopback=True)

        for h in hypotheses:
            evid = await exec_engine.execute_hypothesis(
                hypothesis=h,
                mode=ExecutionMode.AUTHORIZED_LIVE,
                campaign_id=scan_id,
            )
            print(f"  - [{h.check_id}] Result Status: {evid.result_status} (Success={evid.test_status})")
            print(f"    Explanation: {evid.explanation}")
            print(f"    Evidence Keys: {list(evid.evidence_data.keys())}")

    finally:
        db.close()
        server.shutdown()
        kill_ports([port])

if __name__ == "__main__":
    asyncio.run(trace_pipeline())
