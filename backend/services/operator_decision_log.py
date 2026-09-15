"""AihaX Phase 20 — Operator Decision Logging & Cryptographic Audit Chaining.

Architectural Invariants:
1. Human-in-the-Loop Record: Logs every explicit operator decision on recommended security checks.
2. Valid Decision Enum: Enforces APPROVE, REJECT, SKIP, ALREADY_TESTED, REQUEST_REVERIFICATION.
3. Cryptographic Audit Chaining: Every decision computes a SHA-256 event hash chained to the previous audit hash.
4. Tamper Evidence: Any modification to operator ID, timestamp, decision, or budget breaks the cryptographic hash.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from backend.models.database import OperatorDecisionRecord, get_utc_now
from backend.persistence.models import AuditTrailEvent

logger = logging.getLogger("aihax.operator_decision_log")


class OperatorDecisionType:
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    SKIP = "SKIP"
    ALREADY_TESTED = "ALREADY_TESTED"
    REQUEST_REVERIFICATION = "REQUEST_REVERIFICATION"

    ALL = {APPROVE, REJECT, SKIP, ALREADY_TESTED, REQUEST_REVERIFICATION}


@dataclass
class OperatorDecisionDTO:
    """Data transfer object for logged operator decisions."""
    id: str
    recommendation_id: str
    campaign_id: str
    target: str
    check_id: str
    operator_id: str
    decision: str
    timestamp: str
    remaining_budget: int
    audit_hash: str
    reason: Optional[str] = None
    plan_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class OperatorDecisionLogger:
    """Manages audit-chained logging of human operator decisions."""

    @classmethod
    def compute_decision_hash(
        cls,
        prev_hash: str,
        recommendation_id: str,
        campaign_id: str,
        target: str,
        check_id: str,
        operator_id: str,
        decision: str,
        timestamp_str: str,
        remaining_budget: int,
        reason: Optional[str],
    ) -> str:
        """Compute tamper-evident SHA-256 hash for a decision."""
        canonical_str = (
            f"{prev_hash}|{recommendation_id}|{campaign_id}|{target}|"
            f"{check_id}|{operator_id}|{decision}|{timestamp_str}|"
            f"{remaining_budget}|{reason or ''}"
        )
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    @classmethod
    def log_decision(
        cls,
        recommendation_id: str,
        campaign_id: str,
        target: str,
        check_id: str,
        operator_id: str,
        decision: str,
        remaining_budget: int,
        reason: Optional[str] = None,
        plan_hash: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> OperatorDecisionDTO:
        """Log and cryptographically seal an operator decision."""
        decision_upper = decision.upper()
        if decision_upper not in OperatorDecisionType.ALL:
            raise ValueError(f"Invalid decision '{decision}'. Must be one of {OperatorDecisionType.ALL}")

        if not operator_id or not campaign_id or not check_id:
            raise ValueError("operator_id, campaign_id, and check_id are required.")

        now_utc = get_utc_now()
        now_str = now_utc.isoformat()
        rec_id = str(uuid.uuid4())

        # Retrieve previous audit hash if DB available
        prev_hash = "0" * 64
        if db is not None:
            last_event = (
                db.query(AuditTrailEvent)
                .filter(AuditTrailEvent.campaign_id == campaign_id)
                .order_by(AuditTrailEvent.timestamp.desc())
                .first()
            )
            if last_event and last_event.event_hash:
                prev_hash = last_event.event_hash

        audit_hash = cls.compute_decision_hash(
            prev_hash=prev_hash,
            recommendation_id=recommendation_id,
            campaign_id=campaign_id,
            target=target,
            check_id=check_id,
            operator_id=operator_id,
            decision=decision_upper,
            timestamp_str=now_str,
            remaining_budget=remaining_budget,
            reason=reason,
        )

        dto = OperatorDecisionDTO(
            id=rec_id,
            recommendation_id=recommendation_id,
            campaign_id=campaign_id,
            target=target,
            check_id=check_id,
            operator_id=operator_id,
            decision=decision_upper,
            timestamp=now_str,
            reason=reason,
            remaining_budget=remaining_budget,
            plan_hash=plan_hash,
            audit_hash=audit_hash,
        )

        if db is not None:
            # 1. Save Decision record
            record = OperatorDecisionRecord(
                id=rec_id,
                recommendation_id=recommendation_id,
                campaign_id=campaign_id,
                target=target,
                check_id=check_id,
                operator_id=operator_id,
                decision=decision_upper,
                timestamp=now_utc,
                reason=reason,
                remaining_budget=remaining_budget,
                plan_hash=plan_hash,
                audit_hash=audit_hash,
            )
            db.add(record)

            # 2. Append to general AuditTrailEvent chain
            audit_event = AuditTrailEvent(
                id=str(uuid.uuid4()),
                campaign_id=campaign_id,
                event_type="OPERATOR_DECISION",
                actor=operator_id,
                object_id=check_id,
                previous_event_hash=prev_hash,
                event_hash=audit_hash,
                metadata_json=json.dumps({
                    "recommendation_id": recommendation_id,
                    "target": target,
                    "check_id": check_id,
                    "operator_id": operator_id,
                    "decision": decision_upper,
                    "reason": reason,
                    "remaining_budget": remaining_budget,
                    "plan_hash": plan_hash,
                }),
                timestamp=now_utc,
            )
            db.add(audit_event)
            db.commit()
            db.refresh(record)

        return dto

    @classmethod
    def get_decisions_for_campaign(
        cls,
        campaign_id: str,
        db: Optional[Session] = None,
    ) -> List[OperatorDecisionDTO]:
        """List all operator decisions logged for a campaign."""
        if db is None:
            return []

        records = (
            db.query(OperatorDecisionRecord)
            .filter(OperatorDecisionRecord.campaign_id == campaign_id)
            .order_by(OperatorDecisionRecord.timestamp.asc())
            .all()
        )

        return [
            OperatorDecisionDTO(
                id=r.id,
                recommendation_id=r.recommendation_id,
                campaign_id=r.campaign_id,
                target=r.target,
                check_id=r.check_id,
                operator_id=r.operator_id,
                decision=r.decision,
                timestamp=r.timestamp.isoformat() if hasattr(r.timestamp, "isoformat") else str(r.timestamp),
                reason=r.reason,
                remaining_budget=r.remaining_budget,
                plan_hash=r.plan_hash,
                audit_hash=r.audit_hash,
            )
            for r in records
        ]
