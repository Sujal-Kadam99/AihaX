"""AihaX — Phase 13 End-to-End Runtime Truth & Verification Script.

Validates the full Campaign/Target Lifecycle and Runtime Execution Integrity:
1. Cancellation lifecycle & anti-resurrection guarantees
2. Target assignment decoupling and release
3. Fresh campaign start, atomic task seeding, and worker execution
4. Evidence Vault, redaction, and report generation
5. Cryptographic integrity & Diagnostic Runtime Truth
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.models.database import Base, Finding, Program, ProgramScope, Scan
from backend.persistence.models import Campaign, CampaignTarget, EvidenceRecord, ExecutionTask
from backend.persistence.repository import CampaignRepository
from backend.persistence.state_machine import (
    CampaignLifecycleState,
    InvalidStateTransitionError,
    TaskLifecycleState,
)
from backend.services.campaign_operations import CampaignOperationsService
from backend.services.report_generator import generate_scan_report


def run_e2e_runtime_truth_verification():
    print("=" * 75)
    print("AihaX Phase 13 — End-to-End Runtime Truth & Lifecycle Integrity Verification")
    print("=" * 75)

    # 1. Setup in-memory verified SQLite environment
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    db = Session()
    repo = CampaignRepository(db)
    service = CampaignOperationsService(repo)

    # 2. Stage 1: Register Authorized Program & Scope
    print("\n[+] Stage 1: Register Authorized Program & Scope")
    prog_id = "prog-eternal-001"
    program = Program(
        id=prog_id,
        name="Eternal",
        description="Authorized bug bounty program for Eternal/Zomato wildcard",
        created_at=datetime.now(timezone.utc),
    )
    db.add(program)
    prog_scope = ProgramScope(
        id="scope-eternal-001",
        program_id=prog_id,
        in_scope_assets=json.dumps(["*.zomato.com", "https://*.zomato.com/*"]),
        out_of_scope_assets=json.dumps([]),
        allowed_ports=json.dumps([80, 443]),
        excluded_ports=json.dumps([]),
        allowed_schemes=json.dumps(["https", "http"]),
        excluded_paths=json.dumps([]),
        created_at=datetime.now(timezone.utc),
    )
    db.add(prog_scope)
    db.commit()
    print(f"  [PASS] Program registered: ID={program.id}, Scope=*.zomato.com")

    # 3. Stage 2: Create, Start, and Cancel Initial Campaign (Verify Invalidation & Anti-Resurrection)
    print("\n[+] Stage 2: Invalidation & Anti-Resurrection of Cancelled Campaign")
    camp1 = service.create_campaign(
        name="Eternal-Zomato-Web-001",
        target_url="https://app.zomato.com",
        program_id=prog_id,
        in_scope_assets=["https://app.zomato.com"],
        selected_checks=["C001_Reflected_XSS"],
    )
    service.authorize_campaign(camp1.id, authorized_by="lead_operator")
    service.start_campaign(camp1.id, auto_dispatch=True)
    db.commit()
    assert camp1.status == CampaignLifecycleState.RUNNING.value

    # Worker claims initial task
    claimed_1 = service.claim_tasks_for_worker(camp1.id, worker_id="worker_01", limit=1)
    assert len(claimed_1) == 1
    t_camp1 = claimed_1[0]
    print(f"  [PASS] Campaign 1 started and task claimed: Task ID={t_camp1.id}")

    # Operator cancels Campaign 1
    service.cancel_campaign(camp1.id, actor="lead_operator", reason="Operator cancelled testing")
    db.commit()
    assert camp1.status == CampaignLifecycleState.CANCELLED.value
    assert t_camp1.status == TaskLifecycleState.CANCELLED.value
    assert t_camp1.lease_expires_at is None
    print("  [PASS] Campaign 1 status is CANCELLED; task invalidated to CANCELLED")

    # Verify target assignment released for Campaign 1
    targets_c1 = repo.get_targets(camp1.id)
    assert len(targets_c1) == 1
    assert targets_c1[0].target_status == "RELEASED"
    print("  [PASS] Campaign 1 target assignment released without deauthorizing parent program")

    # Verify Crash Recovery cannot resurrect Cancelled Campaign
    t_camp1.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=60)
    db.commit()
    recovered = service.recover_stale_tasks(camp1.id)
    assert len(recovered) == 0
    assert t_camp1.status == TaskLifecycleState.CANCELLED.value
    print("  [PASS] Crash recovery verified: Zero resurrection of cancelled work")

    # Verify Diagnostic Runtime Truth for Cancelled Campaign
    truth_c1 = service.get_campaign_runtime_truth(camp1.id)
    assert truth_c1["status"] == "CANCELLED"
    assert truth_c1["current_phase"] == "CANCELLED"
    assert truth_c1["is_stalled"] is False
    print(f"  [PASS] Diagnostic Runtime Truth for Cancelled Campaign: Phase={truth_c1['current_phase']}, Operation='{truth_c1['active_operation']}'")

    # 4. Stage 3: Launch Fresh Campaign (Verify Real Runtime Execution)
    print("\n[+] Stage 3: Fresh Campaign Launch & Atomic Task Generation")
    camp2 = service.create_campaign(
        name="Eternal-Zomato-Web-002",
        target_url="https://api.zomato.com",
        program_id=prog_id,
        in_scope_assets=["https://api.zomato.com"],
        selected_checks=["C008_Information_Disclosure"],
    )
    service.authorize_campaign(camp2.id, authorized_by="lead_operator")
    service.start_campaign(camp2.id, auto_dispatch=True)
    db.commit()
    assert camp2.status == CampaignLifecycleState.RUNNING.value
    print(f"  [PASS] Fresh Campaign 2 launched: ID={camp2.id}, Status={camp2.status}")

    # 5. Stage 4: Worker Execution on Fresh Campaign
    print("\n[+] Stage 4: Worker Execution on Fresh Campaign")
    claimed_2 = service.claim_tasks_for_worker(camp2.id, worker_id="worker_02", limit=1)
    assert len(claimed_2) == 1
    task2 = claimed_2[0]
    print(f"  [PASS] Worker claimed atomic task: Task ID={task2.id}, Check={task2.check_id}")

    # Ingest genuine evidence and record finding
    from backend.evidence.integrity import compute_evidence_content_hash
    from backend.evidence.redaction import redact_secrets

    raw_req = "GET /v2/profile HTTP/1.1\nHost: api.zomato.com\nAuthorization: Bearer SECRET_TOKEN_123"
    raw_res = "HTTP/1.1 200 OK\nSet-Cookie: session=SECRET_SESSION_XYZ\n\n{\"user_id\":\"12345\"}"
    redacted_req = redact_secrets(raw_req)
    redacted_res = redact_secrets(raw_res)
    assert "SECRET_TOKEN_123" not in redacted_req

    content_hash = compute_evidence_content_hash(
        evidence_type="PROOF",
        target_url="https://api.zomato.com/v2/profile",
        method="GET",
        sanitized_request=redacted_req,
        sanitized_response=redacted_res,
    )
    ev_record = repo.record_evidence(
        campaign_id=camp2.id,
        evidence_type="PROOF",
        target_url="https://api.zomato.com/v2/profile",
        content_hash=content_hash,
        method="GET",
        sanitized_request=redacted_req,
        sanitized_response=redacted_res,
        task_id=task2.id,
    )

    scan_backing = Scan(
        id=camp2.id,
        target_url="https://api.zomato.com",
        status="completed",
        created_at=datetime.now(timezone.utc),
    )
    finding = Finding(
        id="f-truth-002",
        scan_id=camp2.id,
        agent_id=1,
        title="Sensitive API Profile Exposure",
        vuln_type="C008_Information_Disclosure",
        category="disclosure",
        severity="medium",
        affected_url="https://api.zomato.com/v2/profile",
        verdict="Verified",
        verification_status="VERIFIED",
        false_positive=False,
        evidence_ids=f'["{ev_record.id}"]',
    )
    db.add(scan_backing)
    db.add(finding)
    repo.complete_task(task_id=task2.id, worker_id="worker_02")
    db.commit()
    print("  [PASS] Evidence ingested into Vault and Finding verified in database")

    # 6. Stage 5: Report Generation & Download Verification
    print("\n[+] Stage 5: Generate Report & Validate PDF Magic Bytes")
    pdf_bytes = generate_scan_report(db, camp2.id)
    assert pdf_bytes is not None
    assert len(pdf_bytes) > 0
    assert pdf_bytes.startswith(b"%PDF-")
    print(f"  [PASS] PDF Report generated: Size={len(pdf_bytes)} bytes, Magic Header={pdf_bytes[:5].decode('latin1')}")

    # 7. Stage 6: Cryptographic Manifest & Integrity Audit
    print("\n[+] Stage 6: Cryptographic Manifest & Integrity Audit")
    integrity = service.verify_campaign_integrity(camp2.id)
    assert integrity.verified is True
    assert len(integrity.issues) == 0
    hash_preview = (integrity.manifest_hash[:16] + "...") if integrity.manifest_hash else "UNSEALED"
    print(f"  [PASS] Manifest Integrity: verified={integrity.verified}, manifest_hash={hash_preview}")

    # 8. Stage 7: Targets Endpoint Decoupled Status Verification
    print("\n[+] Stage 7: Targets Program API Decoupled Representation")
    from backend.routers.programs import _build_program_response
    prog_resp = _build_program_response(program, db)
    assert prog_resp.status == "AUTHORIZED"
    assert prog_resp.active_campaigns_count == 1  # Camp 2 is active
    assert prog_resp.total_campaigns_count == 2   # Camp 1 (cancelled) + Camp 2 (running)
    assert len(prog_resp.campaigns) == 2
    print(f"  [PASS] Program Status={prog_resp.status}, Active={prog_resp.active_campaigns_count}, Total={prog_resp.total_campaigns_count}")

    # 9. Stage 8: Concrete Target URL vs Scope Wildcard Runtime Truth
    print("\n[+] Stage 8: Concrete Target URL vs Scope Wildcard Runtime Truth")
    from backend.core.scope_validator import ScopeValidator, validate_concrete_target_url
    from backend.routers.programs import _parse_scope_model_to_schema

    prog_shopify_id = "prog-shopify-e2e"
    prog_shopify = Program(
        id=prog_shopify_id,
        name="Shopify Bug Bounty",
        description="Public bounty program for Shopify wildcard scope",
        created_at=datetime.now(timezone.utc),
    )
    db.add(prog_shopify)
    prog_shopify_scope = ProgramScope(
        id="scope-shopify-e2e",
        program_id=prog_shopify_id,
        in_scope_assets=json.dumps(["*.shopify.com", "*.myshopify.com", "https://*.shopify.com/*", "https://*.myshopify.com/*"]),
        out_of_scope_assets=json.dumps([]),
        allowed_ports=json.dumps([80, 443]),
        excluded_ports=json.dumps([]),
        allowed_schemes=json.dumps(["https", "http"]),
        excluded_paths=json.dumps([]),
        created_at=datetime.now(timezone.utc),
    )
    db.add(prog_shopify_scope)
    db.commit()

    # Scope validator evaluates concrete target
    scope_schema = _parse_scope_model_to_schema(prog_shopify.scope)
    validator = ScopeValidator(
        in_scope_assets=scope_schema.in_scope_assets,
        out_of_scope_assets=scope_schema.out_of_scope_assets,
        allowed_ports=scope_schema.allowed_ports,
        excluded_ports=scope_schema.excluded_ports,
        allowed_schemes=scope_schema.allowed_schemes,
        excluded_paths=scope_schema.excluded_paths,
    )

    # 1. Concrete target is in-scope
    decision_concrete = validator.is_url_in_scope("https://example-shop.myshopify.com")
    assert decision_concrete.allowed is True
    assert decision_concrete.status == "IN_SCOPE"
    assert decision_concrete.matched_rule in ("*.myshopify.com", "https://*.myshopify.com/*")
    print(f"  [PASS] Scope validation for concrete target: allowed={decision_concrete.allowed}, status={decision_concrete.status}, matched_rule={decision_concrete.matched_rule}")


    # 2. Wildcard input as target is rejected as INVALID
    decision_wildcard = validator.is_asset_in_scope("*.shopify.com")
    assert decision_wildcard.allowed is False
    assert decision_wildcard.status == "INVALID"
    print(f"  [PASS] Scope validation for wildcard input rejected: allowed={decision_wildcard.allowed}, status={decision_wildcard.status}")

    # 2b. Out of scope target is rejected as DENIED_BY_DEFAULT / OUT_OF_SCOPE
    decision_oos = validator.is_url_in_scope("https://evil.com")
    assert decision_oos.allowed is False
    assert decision_oos.status in ("DENIED_BY_DEFAULT", "OUT_OF_SCOPE")
    print(f"  [PASS] Scope validation for out-of-scope target rejected: allowed={decision_oos.allowed}, status={decision_oos.status}")


    # 3. Create Campaign with concrete target
    camp_shopify = service.create_campaign(
        name="Shopify Store Assessment",
        target_url="https://example-shop.myshopify.com",
        program_id=prog_shopify_id,
        in_scope_assets=["https://example-shop.myshopify.com", "*.shopify.com"],
        selected_checks=["C001_Reflected_XSS"],
    )
    service.authorize_campaign(camp_shopify.id, authorized_by="lead_operator")
    service.start_campaign(camp_shopify.id, auto_dispatch=True)
    db.commit()

    assert camp_shopify.target_url == "https://example-shop.myshopify.com"
    assert "*" not in camp_shopify.target_url

    shopify_targets = repo.get_targets(camp_shopify.id)
    assert len(shopify_targets) == 1
    assert shopify_targets[0].normalized_url == "https://example-shop.myshopify.com"
    assert "*" not in shopify_targets[0].normalized_url

    claimed_shopify = service.claim_tasks_for_worker(camp_shopify.id, worker_id="worker_shopify", limit=1)
    assert len(claimed_shopify) == 1
    task_shopify = claimed_shopify[0]
    assert task_shopify.target_url == "https://example-shop.myshopify.com"
    assert "*" not in task_shopify.target_url
    print(f"  [PASS] Runtime Truth: Campaign.target_url='{camp_shopify.target_url}', Task.target_url='{task_shopify.target_url}' (Zero Wildcard Execution)")

    # 4. Attempting to create campaign with wildcard targets fails closed
    try:
        service.create_campaign(
            name="Invalid Wildcard Campaign",
            target_url="*.shopify.com",
            program_id=prog_shopify_id,
        )
        assert False, "Should have raised ValueError on wildcard target"
    except ValueError as e:
        assert "Wildcard scope rules cannot be used as executable assessment targets" in str(e)
        print(f"  [PASS] Attempt to create campaign with '*.shopify.com' rejected: {e}")

    try:
        service.create_campaign(
            name="Invalid Wildcard URL Campaign",
            target_url="https://*.shopify.com",
            program_id=prog_shopify_id,
        )
        assert False, "Should have raised ValueError on wildcard target URL"
    except ValueError as e:
        assert "Wildcard scope rules cannot be used as executable assessment targets" in str(e)
        print(f"  [PASS] Attempt to create campaign with 'https://*.shopify.com' rejected: {e}")

    # 10. Stage 9: Campaign Worker Dispatch & Live Runtime Heartbeat
    print("\n[+] Stage 9: Campaign Worker Dispatch & Live Runtime Heartbeat")
    import asyncio
    from backend.services.campaign_worker import CampaignWorker
    from backend.services.request_engine import RequestEngine, MockTransport
    import httpx

    # Zero-network MockTransport
    mock_transport = MockTransport(
        default_status=200,
        default_headers={"Content-Type": "application/json", "X-Frame-Options": "DENY"},
        default_body=b'{"status": "ok", "app": "Shopify Storefront Mock"}',
    )
    req_engine = RequestEngine(scope_validator=validator, transport=mock_transport)
    worker = CampaignWorker(worker_id="worker_shopify", request_engine=req_engine)

    # Worker executes task_shopify
    exec_res = asyncio.run(worker.execute_task(task_id=task_shopify.id, session=db, repo=repo))
    assert exec_res["status"] == "completed"
    db.refresh(task_shopify)
    assert task_shopify.status == "COMPLETED"

    # Verify runtime truth reports progress
    truth_shopify = service.get_campaign_runtime_truth(camp_shopify.id)
    assert truth_shopify["status"] in ("RUNNING", "COMPLETED")
    assert truth_shopify["is_stalled"] is False
    assert truth_shopify["tasks_summary"].get("COMPLETED", 0) >= 1
    assert truth_shopify["metrics"]["evidence_count"] >= 1
    print(f"  [PASS] Real Worker Executed Task: Status={task_shopify.status}, Completed Tasks={truth_shopify['tasks_summary'].get('COMPLETED', 0)}, Evidence Count={truth_shopify['metrics']['evidence_count']}")

    # 11. Stage 10: Controlled Local Live Execution Verification (Phase 13.z)
    print("\n[+] Stage 10: Controlled Local Live Execution Verification (Phase 13.z)")
    import socket
    from aiohttp import web
    from backend.tests.fixtures.security_lab.lab_server import create_security_lab_app
    from backend.services.request_engine import AiohttpTransport, RequestSpec

    def _get_free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    async def _run_stage_10():
        # Spin up local lab server
        lab_app = create_security_lab_app()
        runner = web.AppRunner(lab_app)
        await runner.setup()
        port = _get_free_port()
        site = web.TCPSite(runner, "127.0.0.1", port)
        await site.start()
        local_url = f"http://127.0.0.1:{port}"

        try:
            # 1. Authorize local target in ScopeValidator
            local_validator = ScopeValidator(in_scope_assets=[local_url, "127.0.0.1"])
            local_engine = RequestEngine(scope_validator=local_validator, transport=AiohttpTransport())

            # 2. Verify diagnostic endpoints respond
            res_health = await local_engine.execute(RequestSpec(url=f"{local_url}/health", method="GET"))
            assert res_health.success is True and res_health.response_status == 200
            print(f"  [PASS] Local Server Started & Responded at {local_url} (status={res_health.response_status})")

            # 3. Create Campaign & Execute Local Task
            camp_local = service.create_campaign(
                name="Phase 13.z Local Live Verification",
                target_url=local_url,
                selected_checks=["C049_Clickjacking"],
            )
            service.authorize_campaign(camp_local.id, authorized_by="qa_verifier")
            service.start_campaign(camp_local.id, auto_dispatch=True)
            db.commit()

            local_worker = CampaignWorker(worker_id="worker_local_live_01", request_engine=local_engine)
            claimed = repo.claim_tasks(camp_local.id, local_worker.worker_id, limit=1)
            assert len(claimed) == 1
            print(f"  [PASS] Campaign Created, Authorized, Started, and Task Claimed: Task={claimed[0].id}")

            exec_local = await local_worker.execute_task(task_id=claimed[0].id, session=db, repo=repo)
            assert exec_local["status"] == "completed"
            db.refresh(camp_local)
            print(f"  [PASS] Task Executed against Local Target: requests_used={camp_local.requests_used}, status={camp_local.status}")

            # 4. Generate and verify PDF report
            pdf_bytes = generate_scan_report(db, scan_id=camp_local.id)
            assert pdf_bytes.startswith(b"%PDF-")
            print(f"  [PASS] Executive PDF Report Generated & Sealed: Size={len(pdf_bytes)} bytes, MagicHeader=%PDF-")

            # 5. Verify Cryptographic Integrity
            integrity = service.verify_campaign_integrity(camp_local.id)
            assert integrity.verified is True
            print(f"  [PASS] Evidence Manifest Cryptographically Verified: manifest_hash={integrity.manifest_hash[:16]}...")
        finally:
            await runner.cleanup()

    asyncio.run(_run_stage_10())

    print("\n" + "=" * 75)
    print("ALL 10 VERIFICATION STAGES PASSED (100% SUCCESS — ZERO EXTERNAL CALLS)")
    print("=" * 75)
    return True


if __name__ == "__main__":
    success = run_e2e_runtime_truth_verification()
    sys.exit(0 if success else 1)


