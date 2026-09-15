import asyncio
import os
import json
import hashlib
from backend.recon.live_recon_validator import (
    ExecutionOrigin,
    LiveReconValidationEngine,
    ToolValidationStatus,
)
from backend.execution.tool_execution_boundary import ToolExecutionBoundary

async def main():
    os.environ["AIHAX_TOOLS_DIR"] = os.path.abspath("bin/tools")
    print(f"AIHAX_TOOLS_DIR = {os.environ['AIHAX_TOOLS_DIR']}")

    engine = LiveReconValidationEngine(custom_bin_dir=os.environ["AIHAX_TOOLS_DIR"])
    target = "https://www.mitacsc.ac.in"
    campaign_id = "phase27-mitacsc-auth-camp"
    auth_id = "auth-mitacsc-phase27-record-valid"
    pipeline_id = "phase27-pipeline-run-mitacsc"

    print("Executing Phase 27 Live Recon Validation Suite...")
    result = await engine.execute_validation_suite(
        target=target,
        campaign_id=campaign_id,
        authorization_record_id=auth_id,
        operator_confirmed=True,
        scope_assets=[target, "https://*.mitacsc.ac.in"],
        allow_port_scan=False,
        allow_dir_scan=False,
        execution_origin=ExecutionOrigin.PHASE27_CONTROLLED_PIPELINE,
        pipeline_run_id=pipeline_id,
    )

    print(f"Suite Status: {result.suite_status}")
    print(f"Total Evaluated: {result.total_tools_evaluated}")
    print(f"Executed Tools: {result.executed_tools_count}")
    print(f"Live Validated: {result.live_validated_count}")
    print(f"Failed Tools: {result.failed_tools_count}")
    print(f"Blocked Tools: {result.blocked_tools_count}")

    print("\n--- TOOL STATUS BREAKDOWN ---")
    for tool_name, rec in result.tool_records.items():
        print(f"  {tool_name:<14}: status={rec.status.value:<28} exit={rec.exit_code} results={rec.parsed_result_count} stdout_hash={rec.stdout_hash[:16] if rec.stdout_hash else 'None'}")
        if rec.failure_reason:
            print(f"    Failure Reason: {rec.failure_reason}")

    if result.recon_snapshot:
        print(f"\nRecon Snapshot Hash: {result.recon_snapshot.snapshot_hash}")
        print(f"Total Normalized Assets in Snapshot: {len(result.recon_snapshot.normalized_assets)}")
        for a in result.recon_snapshot.normalized_assets[:10]:
            print(f"    - {a.normalized_value} ({a.asset_type}) source={a.source_provider} is_executable={a.is_executable}")

    if result.attack_surface_graph:
        print(f"\nAttack Surface Graph: {result.attack_surface_graph}")

if __name__ == "__main__":
    asyncio.run(main())
