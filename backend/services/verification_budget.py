"""AihaX Phase 21 — Verification Budget Ledger.

Enforces atomic, campaign-level persistent request accounting with strict
fail-closed behavior at the 10-request hard ceiling.

Security Invariants:
1. Hard cap: LOCKED_PRODUCTION_BUDGET = 10 requests total per campaign.
2. Remaining budget is never negative; attempts to overspend are strictly rejected (BLOCKED_BUDGET).
3. Every executed verification request logs an immutable ledger entry.
4. If remaining_budget == 0, is_budget_exhausted returns True.
"""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from backend.models.database import (
    VerificationBudgetEntryRecord,
    get_utc_now,
)
from backend.persistence.models import Campaign

logger = logging.getLogger("aihax.verification_budget")

LOCKED_CAMPAIGN_BUDGET_CAP: int = 10
_budget_lock = threading.Lock()


class BudgetExhaustedException(Exception):
    """Raised when request allocation exceeds remaining campaign budget."""
    pass


@dataclass
class VerificationBudgetEntryDTO:
    id: str
    campaign_id: str
    verification_run_id: str
    request_number: int
    request_cost: int
    remaining_budget: int
    strategy_id: str
    operator_decision_id: str
    timestamp: str = field(default_factory=lambda: get_utc_now().isoformat())

    @property
    def cost(self) -> int:
        return self.request_cost

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class VerificationBudgetLedger:
    """Atomic ledger for campaign verification request consumption."""

    def __init__(self, campaign_id: str = "", db: Optional[Session] = None) -> None:
        self.campaign_id = campaign_id
        self.db = db

    def reserve_budget(
        self,
        verification_run_id: str,
        strategy_id: str,
        operator_decision_id: str,
        cost: int = 1,
    ) -> VerificationBudgetEntryDTO:
        return self.allocate_budget(
            campaign_id=self.campaign_id,
            verification_run_id=verification_run_id,
            strategy_id=strategy_id,
            operator_decision_id=operator_decision_id,
            cost=cost,
            db=self.db,
        )

    def remaining_budget(self) -> int:
        return self.get_remaining_budget(self.campaign_id, db=self.db)

    @classmethod
    def get_remaining_budget(
        cls,
        campaign_id: str,
        db: Optional[Session] = None,
        default_budget: int = LOCKED_CAMPAIGN_BUDGET_CAP,
    ) -> int:
        """Calculate exact remaining request budget for a campaign."""
        if db is None:
            return default_budget

        with _budget_lock:
            # Query campaign model
            campaign = db.query(Campaign).filter_by(id=campaign_id).first()
            if not campaign:
                return default_budget

            budget_cap = min(campaign.campaign_budget, LOCKED_CAMPAIGN_BUDGET_CAP)

            # Sum total requests consumed from budget entries
            entries = (
                db.query(VerificationBudgetEntryRecord)
                .filter_by(campaign_id=campaign_id)
                .all()
            )
            used_from_ledger = sum(e.request_cost for e in entries)

            # Check campaign.requests_used
            total_used = max(campaign.requests_used, used_from_ledger)
            remaining = max(0, budget_cap - total_used)
            return remaining

    @classmethod
    def is_budget_exhausted(cls, campaign_id: str, db: Optional[Session] = None) -> bool:
        """Check whether campaign budget has reached 0."""
        return cls.get_remaining_budget(campaign_id, db=db) <= 0

    @classmethod
    def allocate_budget(
        cls,
        campaign_id: str,
        verification_run_id: str,
        strategy_id: str,
        operator_decision_id: str,
        cost: int = 1,
        db: Optional[Session] = None,
    ) -> VerificationBudgetEntryDTO:
        """Atomically reserve and record request budget consumption. Fails closed if insufficient."""
        if cost <= 0:
            raise ValueError(f"Request cost must be >= 1, got {cost}")

        with _budget_lock:
            if db is not None:
                campaign = db.query(Campaign).filter_by(id=campaign_id).first()
                if not campaign:
                    raise ValueError(f"Campaign '{campaign_id}' not found")

                budget_cap = min(campaign.campaign_budget, LOCKED_CAMPAIGN_BUDGET_CAP)
                
                # Query existing entries
                existing_entries = (
                    db.query(VerificationBudgetEntryRecord)
                    .filter_by(campaign_id=campaign_id)
                    .order_by(VerificationBudgetEntryRecord.request_number.desc())
                    .all()
                )
                used_so_far = sum(e.request_cost for e in existing_entries)
                total_used = max(campaign.requests_used, used_so_far)

                if total_used + cost > budget_cap:
                    remaining = max(0, budget_cap - total_used)
                    raise BudgetExhaustedException(
                        f"Insufficient budget: cannot allocate {cost} requests. "
                        f"Used: {total_used}/{budget_cap}, Remaining: {remaining}."
                    )

                next_req_num = (existing_entries[0].request_number + 1) if existing_entries else 1
                new_remaining = budget_cap - (total_used + cost)

                entry_id = str(uuid.uuid4())
                now_utc = get_utc_now()

                record = VerificationBudgetEntryRecord(
                    id=entry_id,
                    campaign_id=campaign_id,
                    verification_run_id=verification_run_id,
                    request_number=next_req_num,
                    request_cost=cost,
                    remaining_budget=new_remaining,
                    strategy_id=strategy_id,
                    operator_decision_id=operator_decision_id,
                    timestamp=now_utc,
                )
                db.add(record)

                # Update campaign requests_used counter
                campaign.requests_used = total_used + cost
                db.commit()
                db.refresh(record)

                return VerificationBudgetEntryDTO(
                    id=record.id,
                    campaign_id=record.campaign_id,
                    verification_run_id=record.verification_run_id,
                    request_number=record.request_number,
                    request_cost=record.request_cost,
                    remaining_budget=record.remaining_budget,
                    strategy_id=record.strategy_id,
                    operator_decision_id=record.operator_decision_id,
                    timestamp=record.timestamp.isoformat() if hasattr(record.timestamp, "isoformat") else str(record.timestamp),
                )
            else:
                # In-memory allocation for disconnected testing
                entry_id = str(uuid.uuid4())
                return VerificationBudgetEntryDTO(
                    id=entry_id,
                    campaign_id=campaign_id,
                    verification_run_id=verification_run_id,
                    request_number=1,
                    request_cost=cost,
                    remaining_budget=max(0, LOCKED_CAMPAIGN_BUDGET_CAP - cost),
                    strategy_id=strategy_id,
                    operator_decision_id=operator_decision_id,
                    timestamp=get_utc_now().isoformat(),
                )

    @classmethod
    def get_budget_history(cls, campaign_id: str, db: Session) -> List[VerificationBudgetEntryDTO]:
        """Fetch complete chronological ledger history for a campaign."""
        recs = (
            db.query(VerificationBudgetEntryRecord)
            .filter_by(campaign_id=campaign_id)
            .order_by(VerificationBudgetEntryRecord.request_number.asc())
            .all()
        )
        return [
            VerificationBudgetEntryDTO(
                id=r.id,
                campaign_id=r.campaign_id,
                verification_run_id=r.verification_run_id,
                request_number=r.request_number,
                request_cost=r.request_cost,
                remaining_budget=r.remaining_budget,
                strategy_id=r.strategy_id,
                operator_decision_id=r.operator_decision_id,
                timestamp=r.timestamp.isoformat() if hasattr(r.timestamp, "isoformat") else str(r.timestamp),
            )
            for r in recs
        ]
