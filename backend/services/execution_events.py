"""AihaX Evidence Visibility & Execution Transparency Gate.

Provides the canonical execution event model, honest execution status derivation,
cryptographic event hashing, and secret-redacted execution timeline logging.

Invariants:
1. Every executed test must have an observable lifecycle record.
2. Every persisted evidence artifact must be traceable:
   campaign -> target -> test -> request -> evidence -> verification -> finding.
3. An Evidence API failure must never be represented as an empty successful evidence set.
4. COMPLETED execution must expose a deterministic terminal reason.
5. No credentials, tokens, session cookies, or raw secrets are ever stored in events.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlalchemy.orm import Session

from backend.evidence.redaction import redact_secrets

logger = logging.getLogger("aihax.execution_events")


# ──────────────────────────────────────────────────────────────────────────────
# 1. CANONICAL EXECUTION EVENT & STATUS ENUMS
# ──────────────────────────────────────────────────────────────────────────────

class ExecutionEventType(str, Enum):
    """Canonical assessment lifecycle & failure events."""
    # Lifecycle
    CAMPAIGN_CREATED = "CAMPAIGN_CREATED"
    PREFLIGHT_STARTED = "PREFLIGHT_STARTED"
    PREFLIGHT_COMPLETED = "PREFLIGHT_COMPLETED"
    RECON_STARTED = "RECON_STARTED"
    RECON_COMPLETED = "RECON_COMPLETED"
    VULNERABILITY_SELECTION_STARTED = "VULNERABILITY_SELECTION_STARTED"
    VULNERABILITY_SELECTION_COMPLETED = "VULNERABILITY_SELECTION_COMPLETED"
    HYPOTHESIS_CREATED = "HYPOTHESIS_CREATED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_RECEIVED = "APPROVAL_RECEIVED"
    TEST_STARTED = "TEST_STARTED"
    REQUEST_DISPATCHED = "REQUEST_DISPATCHED"
    REQUEST_COMPLETED = "REQUEST_COMPLETED"
    EVIDENCE_CAPTURED = "EVIDENCE_CAPTURED"
    VERIFICATION_COMPLETED = "VERIFICATION_COMPLETED"
    FINDING_CREATED = "FINDING_CREATED"
    QUALITY_GATE_COMPLETED = "QUALITY_GATE_COMPLETED"
    REPORT_GENERATED = "REPORT_GENERATED"
    CAMPAIGN_COMPLETED = "CAMPAIGN_COMPLETED"

    # Verification Lifecycle
    VERIFICATION_STARTED = "VERIFICATION_STARTED"
    VERIFICATION_STRATEGY_SELECTED = "VERIFICATION_STRATEGY_SELECTED"
    FALSE_POSITIVE_CHECK_STARTED = "FALSE_POSITIVE_CHECK_STARTED"
    FALSE_POSITIVE_CHECK_COMPLETED = "FALSE_POSITIVE_CHECK_COMPLETED"
    REPRODUCIBILITY_CHECK_STARTED = "REPRODUCIBILITY_CHECK_STARTED"
    REPRODUCIBILITY_CHECK_COMPLETED = "REPRODUCIBILITY_CHECK_COMPLETED"
    IMPACT_ASSESSMENT_STARTED = "IMPACT_ASSESSMENT_STARTED"
    IMPACT_ASSESSMENT_COMPLETED = "IMPACT_ASSESSMENT_COMPLETED"
    POLICY_ELIGIBILITY_CHECKED = "POLICY_ELIGIBILITY_CHECKED"
    FINDING_VALIDATED = "FINDING_VALIDATED"
    FINDING_REJECTED = "FINDING_REJECTED"
    FINDING_INCONCLUSIVE = "FINDING_INCONCLUSIVE"
    FINDING_HARDENING_ONLY = "FINDING_HARDENING_ONLY"
    FINDING_FALSE_POSITIVE = "FINDING_FALSE_POSITIVE"

    # Blocked / Error
    BLOCKED_SCOPE = "BLOCKED_SCOPE"
    BLOCKED_AUTHORIZATION = "BLOCKED_AUTHORIZATION"
    BLOCKED_SAFETY = "BLOCKED_SAFETY"
    BLOCKED_BUDGET = "BLOCKED_BUDGET"
    EXECUTION_ERROR = "EXECUTION_ERROR"
    EVIDENCE_PERSISTENCE_ERROR = "EVIDENCE_PERSISTENCE_ERROR"


class HonestExecutionStatus(str, Enum):
    """Honest multi-phase status that requires backend proof to transition."""
    NOT_STARTED = "NOT_STARTED"
    PREFLIGHT = "PREFLIGHT"
    RECON = "RECON"
    SELECTING_TESTS = "SELECTING_TESTS"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


# ──────────────────────────────────────────────────────────────────────────────
# 2. EVENT DATA STRUCTURES
# ──────────────────────────────────────────────────────────────────────────────

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ExecutionEvent:
    """Normalized, secret-redacted execution lifecycle event."""
    id: str
    campaign_id: str
    event_type: str
    timestamp: str
    target_url: str = ""
    check_id: Optional[str] = None
    test_id: Optional[str] = None
    request_id: Optional[str] = None
    evidence_id: Optional[str] = None
    finding_id: Optional[str] = None
    status: str = "SUCCESS"
    reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    event_hash: str = ""
    previous_event_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "campaign_id": self.campaign_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "target_url": self.target_url,
            "check_id": self.check_id,
            "test_id": self.test_id,
            "request_id": self.request_id,
            "evidence_id": self.evidence_id,
            "finding_id": self.finding_id,
            "status": self.status,
            "reason": self.reason,
            "metadata": self.metadata,
            "event_hash": self.event_hash,
            "previous_event_hash": self.previous_event_hash,
        }


@dataclass
class ExecutionSummary:
    """Safe, secret-free diagnostic execution summary."""
    campaign_id: str
    status: str
    phase: str
    target: str
    mode: str
    authorization_state: Dict[str, Any]
    tests_selected: int = 0
    tests_started: int = 0
    tests_completed: int = 0
    tests_blocked: int = 0
    tests_inconclusive: int = 0
    tests_detected: int = 0
    tests_validated: int = 0
    evidence_count: int = 0
    finding_count: int = 0
    last_event: Optional[Dict[str, Any]] = None
    terminal_reason: Optional[str] = None
    findings_detected: int = 0
    findings_validated: int = 0
    findings_exploitable: int = 0
    findings_inconclusive: int = 0
    findings_false_positive: int = 0
    findings_hardening_only: int = 0
    findings_not_bounty_eligible: int = 0
    verification_pass_rate: float = 0.0
    verification_failure_rate: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ──────────────────────────────────────────────────────────────────────────────
# 3. EXECUTION EVENT MANAGER
# ──────────────────────────────────────────────────────────────────────────────

class ExecutionEventManager:
    """Central event logging and execution transparency engine."""

    def __init__(self, session: Optional[Session] = None) -> None:
        self.session = session

    def record_event(
        self,
        campaign_id: str,
        event_type: Union[ExecutionEventType, str],
        target_url: str = "",
        check_id: Optional[str] = None,
        test_id: Optional[str] = None,
        request_id: Optional[str] = None,
        evidence_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        status: str = "SUCCESS",
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        actor: str = "system",
    ) -> ExecutionEvent:
        """Create, hash, chain, and persist an execution event into the audit trail."""
        from backend.persistence.models import AuditTrailEvent
        from backend.persistence.repository import CampaignRepository

        event_type_str = event_type.value if isinstance(event_type, ExecutionEventType) else str(event_type)

        # 1. Redact all metadata before persistence or hashing
        clean_meta = {}
        if metadata:
            for k, v in metadata.items():
                if any(s in k.lower() for s in ("password", "secret", "token", "key", "auth", "cookie")):
                    clean_meta[k] = "[REDACTED]"
                elif isinstance(v, str):
                    clean_meta[k] = redact_secrets(v)
                elif isinstance(v, (dict, list)):
                    clean_meta[k] = json.loads(redact_secrets(json.dumps(v)))
                else:
                    clean_meta[k] = v

        clean_reason = redact_secrets(reason) if reason else None
        timestamp_str = _utc_now_iso()
        event_id = str(uuid.uuid4())

        # 2. Get previous event hash for tamper-evident chaining
        prev_hash = None
        if self.session:
            last_ae = (
                self.session.query(AuditTrailEvent)
                .filter(AuditTrailEvent.campaign_id == campaign_id)
                .order_by(AuditTrailEvent.timestamp.desc())
                .first()
            )
            if last_ae:
                prev_hash = last_ae.event_hash

        # 3. Compute deterministic hash over event properties
        payload = {
            "id": event_id,
            "campaign_id": campaign_id,
            "event_type": event_type_str,
            "timestamp": timestamp_str,
            "target_url": target_url,
            "check_id": check_id,
            "test_id": test_id,
            "request_id": request_id,
            "evidence_id": evidence_id,
            "finding_id": finding_id,
            "status": status,
            "reason": clean_reason,
            "metadata": clean_meta,
            "previous_event_hash": prev_hash,
        }
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        event_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        event = ExecutionEvent(
            id=event_id,
            campaign_id=campaign_id,
            event_type=event_type_str,
            timestamp=timestamp_str,
            target_url=target_url,
            check_id=check_id,
            test_id=test_id,
            request_id=request_id,
            evidence_id=evidence_id,
            finding_id=finding_id,
            status=status,
            reason=clean_reason,
            metadata=clean_meta,
            event_hash=event_hash,
            previous_event_hash=prev_hash,
        )

        # 4. Persist to database if session is present
        if self.session:
            repo = CampaignRepository(self.session)
            # Combine canonical attributes inside metadata_json
            full_meta = {
                "target_url": target_url,
                "check_id": check_id,
                "test_id": test_id,
                "request_id": request_id,
                "evidence_id": evidence_id,
                "finding_id": finding_id,
                "status": status,
                "reason": clean_reason,
                "custom": clean_meta,
            }
            ae = repo.append_audit_event(
                campaign_id=campaign_id,
                event_type=event_type_str,
                actor=actor,
                object_id=evidence_id or finding_id or check_id or event_id,
                metadata=full_meta,
            )
            if ae and ae.event_hash:
                event.event_hash = ae.event_hash
                event.previous_event_hash = ae.previous_event_hash

        return event

    def get_timeline(
        self,
        campaign_id: str,
        limit: int = 100,
        offset: int = 0,
        event_type: Optional[str] = None,
    ) -> List[ExecutionEvent]:
        """Fetch chronological execution timeline for campaign."""
        if not self.session:
            return []

        from backend.persistence.models import AuditTrailEvent

        query = (
            self.session.query(AuditTrailEvent)
            .filter(AuditTrailEvent.campaign_id == campaign_id)
            .order_by(AuditTrailEvent.timestamp.asc())
        )

        if event_type:
            query = query.filter(AuditTrailEvent.event_type == event_type)

        raw_events = query.offset(offset).limit(limit).all()
        result: List[ExecutionEvent] = []

        for ae in raw_events:
            meta = {}
            if ae.metadata_json:
                try:
                    meta = json.loads(ae.metadata_json)
                except Exception:
                    meta = {}

            ts_str = ae.timestamp.isoformat() if hasattr(ae.timestamp, "isoformat") else str(ae.timestamp)
            ev = ExecutionEvent(
                id=ae.id,
                campaign_id=ae.campaign_id,
                event_type=ae.event_type,
                timestamp=ts_str,
                target_url=meta.get("target_url", ""),
                check_id=meta.get("check_id"),
                test_id=meta.get("test_id"),
                request_id=meta.get("request_id"),
                evidence_id=meta.get("evidence_id"),
                finding_id=meta.get("finding_id"),
                status=meta.get("status", "SUCCESS"),
                reason=meta.get("reason"),
                metadata=meta.get("custom", {}),
                event_hash=ae.event_hash,
                previous_event_hash=ae.previous_event_hash,
            )
            result.append(ev)

        return result

    def get_execution_summary(self, campaign_id: str) -> ExecutionSummary:
        """Derive an honest, evidence-proven execution summary."""
        if not self.session:
            raise ValueError("Database session required to generate execution summary.")

        from backend.models.database import Finding
        from backend.persistence.models import (
            AuditTrailEvent,
            AuthorizationRecord,
            Campaign,
            EvidenceRecord,
            ExecutionTask,
        )

        campaign = self.session.query(Campaign).filter(Campaign.id == campaign_id).first()
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")

        # Query events, tasks, evidence, findings
        events = (
            self.session.query(AuditTrailEvent)
            .filter(AuditTrailEvent.campaign_id == campaign_id)
            .order_by(AuditTrailEvent.timestamp.asc())
            .all()
        )

        tasks = (
            self.session.query(ExecutionTask)
            .filter(ExecutionTask.campaign_id == campaign_id)
            .all()
        )

        evidence_records = (
            self.session.query(EvidenceRecord)
            .filter(EvidenceRecord.campaign_id == campaign_id)
            .all()
        )
        evidence_count = len(evidence_records)

        findings = (
            self.session.query(Finding)
            .filter(Finding.scan_id == campaign_id)
            .all()
        )
        finding_count = len(findings)

        auth_rec = (
            self.session.query(AuthorizationRecord)
            .filter(AuthorizationRecord.campaign_id == campaign_id)
            .order_by(AuthorizationRecord.authorized_at.desc())
            .first()
        )

        auth_state = {
            "is_authorized": auth_rec is not None and auth_rec.status == "ACTIVE",
            "authorized_by": auth_rec.authorized_by if auth_rec else None,
            "expires_at": auth_rec.expires_at.isoformat() if auth_rec and hasattr(auth_rec.expires_at, "isoformat") else None,
        }

        # Derive event counts
        event_types = [e.event_type for e in events]
        tests_selected = len(tasks)
        tests_started = len([t for t in tasks if t.started_at is not None or t.status in ("RUNNING", "CLAIMED", "COMPLETED")])
        tests_completed = len([t for t in tasks if t.status == "COMPLETED"])
        tests_blocked = len([e for e in event_types if e.startswith("BLOCKED_")])
        tests_inconclusive = len([f for f in findings if f.verdict == "Inconclusive"])
        tests_detected = len([f for f in findings if f.verification_status in ("CANDIDATE", "DETECTED")])
        tests_validated = len([f for f in findings if f.verdict in ("Verified", "Hardening Only") or f.verification_status in ("VERIFIED", "VALIDATED", "HARDENING_ONLY")])

        # Precise Finding Dispositions & Rates
        findings_detected_count = len(findings)
        findings_validated_count = len([
            f for f in findings
            if (getattr(f, "finding_disposition", "") in ("VALIDATED", "VULNERABILITY") or getattr(f, "verification_status", "") in ("VALIDATED", "VERIFIED"))
            and getattr(f, "finding_disposition", "") != "HARDENING_ONLY"
            and getattr(f, "verdict", "") != "Hardening Only"
            and not getattr(f, "false_positive", False)
        ])
        findings_exploitable_count = len([
            f for f in findings
            if getattr(f, "finding_disposition", "") == "EXPLOITABLE"
            or getattr(f, "verification_status", "") == "EXPLOITABLE"
        ])
        findings_hardening_only_count = len([
            f for f in findings
            if getattr(f, "finding_disposition", "") == "HARDENING_ONLY"
            or getattr(f, "verification_status", "") == "HARDENING_ONLY"
            or getattr(f, "verdict", "") == "Hardening Only"
        ])
        findings_false_positive_count = len([
            f for f in findings
            if getattr(f, "finding_disposition", "") == "FALSE_POSITIVE"
            or getattr(f, "verification_status", "") in ("FALSE_POSITIVE", "REJECTED")
            or getattr(f, "false_positive", False)
        ])
        findings_inconclusive_count = len([
            f for f in findings
            if (getattr(f, "finding_disposition", "") == "INCONCLUSIVE" or getattr(f, "verification_status", "") == "INCONCLUSIVE" or getattr(f, "verdict", "") == "Inconclusive")
            and f not in [x for x in findings if getattr(x, "finding_disposition", "") in ("HARDENING_ONLY", "FALSE_POSITIVE", "VALIDATED", "VULNERABILITY", "EXPLOITABLE")]
        ])
        findings_not_bounty_eligible_count = len([
            f for f in findings
            if getattr(f, "finding_disposition", "") == "NOT_BOUNTY_ELIGIBLE"
        ])

        evaluated_count = findings_validated_count + findings_exploitable_count + findings_hardening_only_count + findings_false_positive_count
        verification_pass_rate = round((findings_validated_count + findings_exploitable_count) / max(1, evaluated_count), 4) if evaluated_count > 0 else 0.0
        verification_failure_rate = round(findings_false_positive_count / max(1, evaluated_count), 4) if evaluated_count > 0 else 0.0

        # If tests were selected via VULNERABILITY_SELECTION_COMPLETED event
        for ev in events:
            if ev.event_type == ExecutionEventType.VULNERABILITY_SELECTION_COMPLETED.value and ev.metadata_json:
                try:
                    m = json.loads(ev.metadata_json)
                    c_meta = m.get("custom", {})
                    if "selected_count" in c_meta and tests_selected == 0:
                        tests_selected = c_meta["selected_count"]
                    if "executed_count" in c_meta and tests_completed == 0:
                        tests_completed = c_meta["executed_count"]
                except Exception:
                    pass

        # Determine Honest Status
        status = HonestExecutionStatus.NOT_STARTED.value
        phase = "NOT_STARTED"
        terminal_reason = None

        if campaign.status == "CANCELLED":
            status = HonestExecutionStatus.CANCELLED.value
            phase = "CANCELLED"
            terminal_reason = "Cancelled by operator."
        elif tests_blocked > 0 and tests_started == 0:
            status = HonestExecutionStatus.BLOCKED.value
            phase = "BLOCKED"
            # Find the blocking reason
            for e in reversed(events):
                if e.event_type.startswith("BLOCKED_"):
                    m = json.loads(e.metadata_json) if e.metadata_json else {}
                    terminal_reason = m.get("reason") or f"Execution halted: {e.event_type}"
                    break
        elif campaign.status == "DRAFT":
            status = HonestExecutionStatus.NOT_STARTED.value
            phase = "DRAFT"
        elif campaign.status == "AUTHORIZED" and tests_started == 0:
            status = HonestExecutionStatus.AWAITING_APPROVAL.value
            phase = "AUTHORIZED"
        elif campaign.status in ("RUNNING", "QUEUED"):
            if tests_completed < tests_selected and tests_started > 0:
                status = HonestExecutionStatus.EXECUTING.value
                phase = "EXECUTING"
            elif any(e == ExecutionEventType.RECON_STARTED.value for e in event_types) and not any(e == ExecutionEventType.RECON_COMPLETED.value for e in event_types):
                status = HonestExecutionStatus.RECON.value
                phase = "RECON"
            elif any(e == ExecutionEventType.PREFLIGHT_STARTED.value for e in event_types) and not any(e == ExecutionEventType.PREFLIGHT_COMPLETED.value for e in event_types):
                status = HonestExecutionStatus.PREFLIGHT.value
                phase = "PREFLIGHT"
            elif any(e == ExecutionEventType.VULNERABILITY_SELECTION_STARTED.value for e in event_types) and not any(e == ExecutionEventType.VULNERABILITY_SELECTION_COMPLETED.value for e in event_types):
                status = HonestExecutionStatus.SELECTING_TESTS.value
                phase = "SELECTING_TESTS"
            elif finding_count > 0 and tests_validated == 0:
                status = HonestExecutionStatus.VERIFYING.value
                phase = "VERIFYING"
            else:
                status = HonestExecutionStatus.EXECUTING.value
                phase = "EXECUTING"
        elif campaign.status == "COMPLETED":
            status = HonestExecutionStatus.COMPLETED.value
            phase = "COMPLETED"
            if evidence_count == 0 and tests_completed > 0:
                terminal_reason = "Execution completed. No evidence artifacts were captured."
            elif evidence_count > 0:
                terminal_reason = f"Execution completed with {evidence_count} evidence artifacts captured."
            else:
                terminal_reason = "Execution completed."

        last_event_dict = None
        if events:
            le = events[-1]
            le_meta = json.loads(le.metadata_json) if le.metadata_json else {}
            last_event_dict = {
                "id": le.id,
                "event_type": le.event_type,
                "timestamp": le.timestamp.isoformat() if hasattr(le.timestamp, "isoformat") else str(le.timestamp),
                "reason": le_meta.get("reason"),
            }

        return ExecutionSummary(
            campaign_id=campaign.id,
            status=status,
            phase=phase,
            target=campaign.target_url,
            mode=campaign.mode,
            authorization_state=auth_state,
            tests_selected=tests_selected,
            tests_started=tests_started,
            tests_completed=tests_completed,
            tests_blocked=tests_blocked,
            tests_inconclusive=tests_inconclusive,
            tests_detected=tests_detected,
            tests_validated=tests_validated,
            evidence_count=evidence_count,
            finding_count=finding_count,
            last_event=last_event_dict,
            terminal_reason=terminal_reason,
            findings_detected=findings_detected_count,
            findings_validated=findings_validated_count,
            findings_exploitable=findings_exploitable_count,
            findings_inconclusive=findings_inconclusive_count,
            findings_false_positive=findings_false_positive_count,
            findings_hardening_only=findings_hardening_only_count,
            findings_not_bounty_eligible=findings_not_bounty_eligible_count,
            verification_pass_rate=verification_pass_rate,
            verification_failure_rate=verification_failure_rate,
        )
