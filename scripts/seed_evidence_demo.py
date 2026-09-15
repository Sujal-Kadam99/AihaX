"""Seed script to ensure EV-001, demo campaign, and timeline events exist in db/aihax.db."""

import hashlib
import json
from datetime import datetime, timedelta, timezone

from backend.models.database import Base, Scan, get_session_factory
from backend.persistence.models import (
    AuthorizationRecord,
    Campaign,
    EvidenceRecord,
)
from backend.services.execution_events import (
    ExecutionEventManager,
    ExecutionEventType,
)


def seed_demo_evidence():
    factory = get_session_factory()
    db = factory()

    cid = "camp-demo-001"
    now = datetime.now(timezone.utc)

    # 1. Ensure Campaign
    camp = db.query(Campaign).filter_by(id=cid).first()
    if not camp:
        camp = Campaign(
            id=cid,
            name="Observability Demo Campaign",
            target_url="https://example.com/demo",
            mode="SIMULATION",
            status="COMPLETED",
            manifest_hash="demo-manifest-hash-001",
            requests_used=1,
            campaign_budget=100,
            created_at=now - timedelta(minutes=10),
            started_at=now - timedelta(minutes=9),
            completed_at=now - timedelta(minutes=1),
        )
        db.add(camp)
    else:
        camp.status = "COMPLETED"
        camp.requests_used = 1

    # 2. Ensure Scan record
    scan = db.query(Scan).filter_by(id=cid).first()
    if not scan:
        scan = Scan(
            id=cid,
            target_url="https://example.com/demo",
            total_findings=1,
        )
        db.add(scan)

    # 3. Ensure Authorization Record
    auth = db.query(AuthorizationRecord).filter_by(campaign_id=cid).first()
    if not auth:
        auth = AuthorizationRecord(
            id="auth-demo-001",
            campaign_id=cid,
            authorized_by="security_officer_demo",
            authorization_type="explicit_scope_consent",
            authorization_reference="REF-DEMO-001",
            authorized_at=now - timedelta(minutes=10),
            expires_at=now + timedelta(hours=24),
            scope_hash=hashlib.sha256(b"https://example.com/demo").hexdigest(),
            status="ACTIVE",
        )
        db.add(auth)

    # 4. Ensure Evidence EV-001
    ev_hash = hashlib.sha256(b"EV-001: differential proof HTTP 200 OK").hexdigest()
    ev = db.query(EvidenceRecord).filter_by(id="EV-001").first()
    if not ev:
        ev = EvidenceRecord(
            id="EV-001",
            campaign_id=cid,
            finding_id="FINDING-DEMO-001",
            task_id="TASK-DEMO-001",
            request_id="REQ-DEMO-001",
            evidence_type="PROOF",
            target_url="https://example.com/demo/api/v1/auth",
            method="GET",
            sanitized_request="GET /demo/api/v1/auth HTTP/1.1\nHost: example.com\nAuthorization: Bearer [REDACTED]",
            sanitized_response='HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"status": "authenticated", "role": "admin", "token": "[REDACTED]"}',
            payload_summary="Differential response inspection confirmed HTTP 200 OK with authenticated role.",
            content_hash=ev_hash,
            chain_hash=hashlib.sha256(ev_hash.encode()).hexdigest(),
            created_at=now - timedelta(minutes=5),
        )
        db.add(ev)
    else:
        ev.campaign_id = cid
        ev.content_hash = ev_hash

    db.commit()

    # 5. Seed Timeline Events with ExecutionEventManager
    event_mgr = ExecutionEventManager(db)
    existing_events = event_mgr.get_timeline(cid)
    if not existing_events:
        event_mgr.record_event(
            campaign_id=cid,
            event_type=ExecutionEventType.TEST_STARTED,
            metadata={"check_id": "C013_Admin_Bypass", "target": "https://example.com/demo/api/v1/auth"},
        )
        event_mgr.record_event(
            campaign_id=cid,
            event_type=ExecutionEventType.REQUEST_DISPATCHED,
            metadata={"url": "https://example.com/demo/api/v1/auth", "method": "GET"},
        )
        event_mgr.record_event(
            campaign_id=cid,
            event_type=ExecutionEventType.REQUEST_COMPLETED,
            metadata={"status_code": 200, "latency_ms": 42},
        )
        event_mgr.record_event(
            campaign_id=cid,
            event_type=ExecutionEventType.EVIDENCE_CAPTURED,
            metadata={"evidence_id": "EV-001", "content_hash": ev_hash, "type": "PROOF"},
        )
        event_mgr.record_event(
            campaign_id=cid,
            event_type=ExecutionEventType.VERIFICATION_COMPLETED,
            metadata={"finding_id": "FINDING-DEMO-001", "result": "CONFIRMED"},
        )
        event_mgr.record_event(
            campaign_id=cid,
            event_type=ExecutionEventType.CAMPAIGN_COMPLETED,
            metadata={"findings_count": 1, "evidence_count": 1, "status": "COMPLETED"},
        )

    print(f"Successfully seeded demo campaign {cid} with EV-001 (hash: {ev_hash}) and lifecycle events!")


if __name__ == "__main__":
    seed_demo_evidence()
