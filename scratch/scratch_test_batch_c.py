import asyncio
import json
import logging
import subprocess
import time
from backend.services.verification_engine import VerificationEngine, VerificationContext
from backend.services.request_engine import RequestEngine
from backend.core.scope_validator import ScopeValidator
from backend.models.database import Finding
from scratch.kill_scratch_ports import kill
from backend.services.verification_strategies.mass_assignment_strategy import MassAssignmentVerificationStrategy
from backend.services.verification_strategies.parameter_tampering_strategy import ParameterTamperingVerificationStrategy
from backend.services.verification_strategies.race_condition_strategy import RaceConditionVerificationStrategy

logging.basicConfig(level=logging.INFO)

async def run_batch_c():
    kill([5006])
    
    print("\n--- Starting Mock E-Commerce App ---")
    app_proc = subprocess.Popen(["python", "scratch/ecommerce_app.py"])
    time.sleep(2)
    
    scope = ScopeValidator(in_scope_assets=["http://127.0.0.1:5006"])
    req_engine = RequestEngine(scope_validator=scope)
    
    print("\n--- Running Batch C Verifications ---")
    
    try:
        # 1. Mass Assignment (C070)
        print("\n[C070] Testing Mass Assignment...")
        payload = json.dumps({"name": "Eve", "role": "admin"})
        f1 = Finding(id="F1", affected_url="http://127.0.0.1:5006/api/user/1", vuln_type="Mass Assignment", category="Business Logic", severity="High", title="Mass Assignment")
        ctx1 = VerificationContext(f1.id, f1.affected_url, {"payload": payload}, req_engine, check_id="C070", authorization_confirmed=True)
        strat1 = MassAssignmentVerificationStrategy()
        res1 = await strat1.verify(ctx1)
        print(f"C070 Result: {res1.status.name} - {res1.reason_description}")

        # 2. Parameter Tampering (C073)
        print("\n[C073] Testing Parameter Tampering...")
        f2 = Finding(id="F2", affected_url="http://127.0.0.1:5006/api/buy?price=10.0", vuln_type="Parameter Tampering", category="Business Logic", severity="High", title="Tampering")
        ctx2 = VerificationContext(f2.id, f2.affected_url, {"observed_data": {"parameter": "price"}}, req_engine, check_id="C073", authorization_confirmed=True)
        strat2 = ParameterTamperingVerificationStrategy()
        res2 = await strat2.verify(ctx2)
        print(f"C073 Result: {res2.status.name} - {res2.reason_description}")

        # 3. Race Condition (C075)
        print("\n[C075] Testing Race Condition...")
        f3 = Finding(id="F3", affected_url="http://127.0.0.1:5006/api/redeem", vuln_type="Race Condition", category="Business Logic", severity="High", title="Race Condition")
        ctx3 = VerificationContext(f3.id, f3.affected_url, {"observed_data": {"permit_race_condition_testing": True}}, req_engine, check_id="C075", authorization_confirmed=True)
        strat3 = RaceConditionVerificationStrategy()
        res3 = await strat3.verify(ctx3)
        print(f"C075 Result: {res3.status.name} - {res3.reason_description}")
        
        print("\n--- Testing Safeguard (C075) ---")
        f4 = Finding(id="F4", affected_url="http://127.0.0.1:5006/api/redeem", vuln_type="Race Condition", category="Business Logic", severity="High", title="Race Condition Safeguard")
        ctx4 = VerificationContext(f4.id, f4.affected_url, {"observed_data": {}}, req_engine, check_id="C075", authorization_confirmed=True)
        res4 = await strat3.verify(ctx4)
        print(f"C075 Safeguard Result: {res4.status.name} - {res4.reason_description}")
    finally:
        print("\n--- Cleaning up ---")
        app_proc.terminate()
        app_proc.wait()

if __name__ == "__main__":
    asyncio.run(run_batch_c())
