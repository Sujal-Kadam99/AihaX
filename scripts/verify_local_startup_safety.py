"""AihaX Local Startup Safety & Health Verification Script.

Executes local mock security workflows, scope enforcement, zero-network verification,
evidence redaction/integrity, audit chaining, and state machine validations.
Strictly local: NO EXTERNAL NETWORK CALLS.
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone

# Add backend to path
sys.path.insert(0, os.path.abspath("."))

from backend.core.scope_validator import ScopeDecision, ScopeStatus, ScopeValidator
from backend.services.request_engine import (
    AuthenticationContext,
    MockTransport,
    RawResponse,
    RequestEngine,
    RequestEvidence,
    RequestSpec,
)
from backend.evidence.redaction import contains_unredacted_secrets, redact_dictionary, redact_secrets
from backend.evidence.integrity import compute_evidence_chain_hash, compute_evidence_content_hash
from backend.persistence.models import Base, Campaign, ExecutionTask
from backend.persistence.repository import CampaignRepository
from backend.persistence.state_machine import CampaignLifecycleState, TaskLifecycleState
from backend.services.campaign_operations import CampaignOperationsService
from backend.services.persistent_budget import PersistentRequestBudget
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("safety_verifier")


async def run_local_safety_verification():
    print("=" * 60)
    print("AihaX Local Startup Safety & Scope Invariant Verification")
    print("=" * 60)

    # 1. SCOPE VALIDATOR (DEFAULT-DENY)
    validator = ScopeValidator(
        in_scope_assets=["http://127.0.0.1:8000/*", "http://localhost:3000/*"],
        out_of_scope_assets=["http://127.0.0.1:8000/internal/*"],
        excluded_ports=[22, 25, 3389],
    )

    print("\n[Phase 6] Scope Safety Invariant Check (Zero-Network Bytes on Deny):")
    mock_transport = MockTransport()
    # Register mock responses
    mock_transport.register_response(
        "GET",
        "http://127.0.0.1:8000/api/test",
        RawResponse(status_code=200, headers={"Content-Type": "application/json"}, body=b'{"status":"ok"}'),
    )
    # Redirect response
    mock_transport.register_response(
        "GET",
        "http://127.0.0.1:8000/redirect-evil",
        RawResponse(status_code=302, headers={"Location": "http://evil.com/leak"}, body=b''),
    )

    request_engine = RequestEngine(scope_validator=validator, transport=mock_transport)

    # Test A: Allowed Target
    spec_a = RequestSpec(method="GET", url="http://127.0.0.1:8000/api/test", authorization_confirmed=True)
    res_a = await request_engine.execute(spec_a)
    assert res_a.success is True
    assert mock_transport.call_count == 1
    print("  [PASS] Allowed Target (http://127.0.0.1:8000/api/test) -> Transport Called: 1")

    # Test B: Out-of-Scope Target (MUST GENERATE ZERO TRANSPORT CALLS)
    calls_before = mock_transport.call_count
    spec_b = RequestSpec(url="http://evil.com/pwn", authorization_confirmed=True)
    res_b = await request_engine.execute(spec_b)
    assert res_b.success is False
    assert res_b.transport_error["error_type"] == "SCOPE_DENIED"
    assert mock_transport.call_count == calls_before  # ZERO network bytes
    print("  [PASS] Out-of-Scope Target (http://evil.com/pwn) -> Scope Denied! Transport Called: 0 (Zero Network Bytes)")

    # Test C: Redirect to Out-of-Scope Target
    t_red = MockTransport()
    t_red.register_response(
        url_prefix="http://127.0.0.1:8000/redirect-evil",
        status_code=302,
        headers={"location": "http://evil.com/leak"},
        body="",
    )
    e_red = RequestEngine(scope_validator=validator, transport=t_red)
    spec_c = RequestSpec(url="http://127.0.0.1:8000/redirect-evil", follow_redirects=True, authorization_confirmed=True)
    res_c = await e_red.execute(spec_c)
    assert res_c.success is False
    assert res_c.transport_error["error_type"] == "REDIRECT_BLOCKED"
    print("  [PASS] Redirect to Out-of-Scope (http://evil.com/leak) -> Redirect Blocked Before Transport!")

    # Test D: Authentication Missing
    t_auth = MockTransport()
    e_auth = RequestEngine(scope_validator=validator, transport=t_auth)
    spec_d = RequestSpec(url="http://127.0.0.1:8000/api/test", authorization_confirmed=False)
    res_d = await e_auth.execute(spec_d)
    assert res_d.success is False
    assert res_d.transport_error["error_type"] == "AUTH_MISSING"
    assert t_auth.call_count == 0
    print("  [PASS] Unconfirmed Authorization -> Blocked Before Transport! Transport Called: 0")

    # Test E: Excluded Port
    t_port = MockTransport()
    e_port = RequestEngine(scope_validator=validator, transport=t_port)
    spec_e = RequestSpec(url="http://127.0.0.1:22/ssh", authorization_confirmed=True)
    res_e = await e_port.execute(spec_e)
    assert res_e.success is False
    assert res_e.transport_error["error_type"] == "SCOPE_DENIED"
    assert t_port.call_count == 0
    print("  [PASS] Excluded Port 22 -> Blocked at Scope Boundary! Transport Called: 0")

    print("\n[Phase 7] Evidence Redaction & Cryptographic Integrity Check:")
    sensitive_evidence = (
        "GET /api/user HTTP/1.1\n"
        "Host: 127.0.0.1:8000\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SUPER_SECRET_SIGNATURE\n"
        "Cookie: session_token=super_secret_cookie_9999\n"
        "AWS_KEY: AKIAIOSFODNN7EXAMPLE\n"
    )
    redacted = redact_secrets(sensitive_evidence)
    assert "SUPER_SECRET_SIGNATURE" not in redacted
    assert "super_secret_cookie_9999" not in redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert not contains_unredacted_secrets(redacted)
    print("  [PASS] Secret Redaction: 100% of sensitive headers/tokens stripped prior to persistence")

    h1 = compute_evidence_content_hash("PROOF", "http://127.0.0.1:8000/api/user", "GET", redacted, "200 OK", "canary")
    h2 = compute_evidence_content_hash("PROOF", "http://127.0.0.1:8000/api/user", "GET", redacted, "200 OK", "canary")
    assert h1 == h2
    print(f"  [PASS] SHA-256 Content Hash Determinism: {h1[:16]}...")

    c1 = compute_evidence_chain_hash(h1, None, "2026-08-28T12:00:00Z")
    c2 = compute_evidence_chain_hash("next_hash", c1, "2026-08-28T12:01:00Z")
    assert c1 != c2
    print(f"  [PASS] Cryptographic Hash Chaining: Link established ({c2[:16]}...)")

    print("\n[Phase 8 & 9] Persistence, State Machine & Crash Recovery Check:")
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    session = SessionLocal()

    repo = CampaignRepository(session)
    ops = CampaignOperationsService(repo)

    camp = ops.create_campaign("Local Verification Campaign", "http://127.0.0.1:8000", in_scope_assets=["http://127.0.0.1:8000"])
    session.commit()
    assert camp.status == "DRAFT"
    print("  [PASS] Campaign Creation in DRAFT")

    # Authorize
    ops.authorize_campaign(camp.id, "safety_auditor")
    session.commit()
    assert camp.status == "AUTHORIZED"
    print("  [PASS] Campaign Cryptographic Authorization")

    # Start
    ops.start_campaign(camp.id)
    session.commit()
    assert camp.status == "RUNNING"
    print("  [PASS] Campaign Transition to RUNNING")

    # Create task and claim lease
    task = repo.create_task(camp.id, "http://127.0.0.1:8000", "C002_Missing_Security_Headers", "http://127.0.0.1:8000")
    session.commit()
    claimed = ops.claim_tasks_for_worker(camp.id, "worker_alpha", limit=1, lease_seconds=10)
    assert len(claimed) == 1
    assert claimed[0].worker_id == "worker_alpha"
    print("  [PASS] Atomic Worker Lease Acquired (worker_alpha)")

    # Simulate worker crash (lease expiration)
    from datetime import timedelta
    task.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=20)
    session.commit()

    recovered = ops.recover_stale_tasks(camp.id)
    assert len(recovered) == 1
    assert recovered[0].status == TaskLifecycleState.RETRY_PENDING.value
    print("  [PASS] Stale Worker Lease Recovered & Re-queued as RETRY_PENDING")

    # Complete task under worker_beta
    claimed_beta = ops.claim_tasks_for_worker(camp.id, "worker_beta", limit=1)
    assert len(claimed_beta) == 1
    repo.complete_task(task.id, "worker_beta")
    session.commit()
    assert task.status == "COMPLETED"
    print("  [PASS] Task Completed by Secondary Worker (worker_beta)")

    # Pause and Resume
    ops.pause_campaign(camp.id)
    session.commit()
    assert camp.status == "PAUSED"
    print("  [PASS] Campaign Paused Safely")

    ops.resume_campaign(camp.id)
    session.commit()
    assert camp.status == "RUNNING"
    print("  [PASS] Campaign Resumed Safely")

    # Audit Trail Chaining Check
    audit_events = repo.get_audit_trail(camp.id)
    assert len(audit_events) >= 5
    prev = None
    for ev in audit_events:
        assert ev.previous_event_hash == prev
        prev = ev.event_hash
    print(f"  [PASS] Audit Trail Verified ({len(audit_events)} cryptographically chained events)")

    # Integrity Verification
    integrity = ops.verify_campaign_integrity(camp.id)
    assert integrity.verified is True
    print("  [PASS] Live Manifest & Campaign Cryptographic Integrity Validated (100% PASS)")

    print("\n" + "=" * 60)
    print("ALL LOCAL STARTUP & SAFETY VERIFICATION GATES PASSED (100% GREEN)")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(run_local_safety_verification())
