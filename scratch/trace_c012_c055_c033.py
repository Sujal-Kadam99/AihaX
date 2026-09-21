import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.agents.recon_agent import ReconAgent, ReconExecutionConfig
from backend.services.vulnerability_test_selector import VulnerabilityTestSelector
from backend.services.vulnerability_hypothesis_engine import VulnerabilityHypothesisEngine
from backend.services.vulnerability_execution_engine import VulnerabilityExecutionEngine, ExecutionMode
from backend.services.request_engine import RequestEngine, AiohttpTransport
from backend.core.scope_validator import ScopeValidator
from backend.models.database import get_session_factory
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

async def trace_checks():
    port = 5005
    server = start_vuln_server(port)
    target_url = f"http://127.0.0.1:{port}"
    scan_id = "trace-checks-1"

    factory = get_session_factory()
    db = factory()
    try:
        recon = ReconAgent(scan_id, db, {
            "target_url": target_url,
            "authorization_confirmed": True,
            "in_scope_assets": [target_url, "127.0.0.1"],
            "allow_loopback": True,
            "execution_mode": "AUTHORIZED_LIVE_RECON",
            "timeout_per_tool": 8,
        })
        attack_surface = await recon.execute()
        snapshot = recon.recon_snapshot

        print("\n=== [1] RECON DISCOVERED ENDPOINTS ===")
        endpoints = attack_surface.get("endpoints", [])
        for ep in sorted(set(endpoints)):
            print(f"  - {ep}")

        print("\n=== [2] VULNERABILITY TEST SELECTOR EVALUATION ===")
        selector = VulnerabilityTestSelector()
        matrix = selector.select_tests(
            target_url=target_url,
            recon_snapshot=snapshot,
            authorization_confirmed=True,
            in_scope_assets=[target_url, "127.0.0.1"],
            allow_loopback=True,
        )

        target_checks = ["C003", "C004", "C012", "C033", "C055"]
        for e in matrix.entries:
            if e.check_id in target_checks or any(c in e.vulnerability_id for c in target_checks):
                print(f"\nCheck: {e.check_id} ({e.vulnerability_id})")
                print(f"  Applicability       : {e.applicability}")
                print(f"  Priority            : {e.priority}")
                print(f"  Recommended Targets : {e.recommended_targets}")
                print(f"  Recommended Params  : {e.recommended_parameters}")
                print(f"  Reasons             : {e.reasons}")

        print("\n=== [3] HYPOTHESIS ENGINE GENERATION ===")
        hypo_engine = VulnerabilityHypothesisEngine()
        hypotheses = hypo_engine.generate_hypotheses(matrix, campaign_id=scan_id)
        
        matched_hyps = [h for h in hypotheses if h.check_id in target_checks]
        print(f"Total hypotheses generated: {len(hypotheses)}")
        print(f"Hypotheses for target checks ({len(matched_hyps)}):")
        for h in matched_hyps:
            print(f"  - [{h.check_id}] HypID={h.hypothesis_id}, Target={h.endpoint}, Method={h.method}")

        print("\n=== [4] EXECUTION ENGINE RUN ON TARGET HYPOTHESES ===")
        scope_val = ScopeValidator(in_scope_assets=[target_url, "127.0.0.1"])
        re = RequestEngine(scope_validator=scope_val, transport=AiohttpTransport())
        exec_engine = VulnerabilityExecutionEngine(request_engine=re, scope_validator=scope_val, allow_loopback=True)

        for h in matched_hyps:
            evid = await exec_engine.execute_hypothesis(
                hypothesis=h,
                mode=ExecutionMode.AUTHORIZED_LIVE,
                operator_id="admin",
                operator_approval_id="appr-test",
                campaign_id=scan_id,
            )
            print(f"\nExecuted [{h.check_id}] on {h.endpoint}:")
            print(f"  Result Status : {evid.result_status}")
            print(f"  Test Status   : {evid.test_status}")
            print(f"  Explanation   : {evid.explanation}")

    finally:
        db.close()
        server.shutdown()
        kill_ports([port])

if __name__ == "__main__":
    asyncio.run(trace_checks())
