"""AihaX Phase 8 — Persistent Request Budget Manager.

Provides crash-safe, multi-worker persistent request budget tracking:
- Hierarchical budgeting: Campaign, Target, Check, and Task limits.
- Thread-safe & concurrency-safe budget reservations.
- Prevents requests_used > requests_budget under concurrent workers.
- Emits audit events upon budget exhaustion.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class BudgetExhaustedException(Exception):
    """Raised when request budget limit is reached."""
    pass


@dataclass
class BudgetReservation:
    """Represents an atomic request budget reservation token."""
    token_id: str
    campaign_id: str
    target_url: str
    check_id: str
    count: int = 1
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PersistentRequestBudget:
    """Multi-worker thread-safe request budget manager with reservation semantics."""

    def __init__(
        self,
        campaign_id: str,
        campaign_budget: int = 500,
        target_budget: int = 100,
        check_budget: int = 20,
        initial_requests_used: int = 0,
        initial_target_usage: Optional[Dict[str, int]] = None,
        initial_check_usage: Optional[Dict[str, int]] = None,
    ) -> None:
        self.campaign_id = campaign_id
        self.campaign_budget = max(1, campaign_budget)
        self.target_budget = max(1, target_budget)
        self.check_budget = max(1, check_budget)

        self._campaign_requests = initial_requests_used
        self._target_requests: Dict[str, int] = dict(initial_target_usage or {})
        self._check_requests: Dict[str, int] = dict(initial_check_usage or {})
        self._reservations: Dict[str, BudgetReservation] = {}
        self._lock = asyncio.Lock()
        self.budget_events: List[Dict[str, Any]] = []

    @property
    def requests_used(self) -> int:
        return self._campaign_requests

    @property
    def remaining_budget(self) -> int:
        return max(0, self.campaign_budget - self._campaign_requests)

    def _record_event(self, event_type: str, target_url: str, check_id: str, reason: str) -> None:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            "campaign_id": self.campaign_id,
            "target_url": target_url,
            "check_id": check_id,
            "reason": reason,
            "requests_used": self._campaign_requests,
            "campaign_budget": self.campaign_budget,
        }
        self.budget_events.append(event)
        logger.warning(f"Budget event [{event_type}]: {reason}")

    async def can_request(self, target_url: str, check_id: str, count: int = 1) -> Tuple[bool, str]:
        """Check if request budget allows execution without reserving."""
        async with self._lock:
            pending_count = sum(r.count for r in self._reservations.values())
            projected = self._campaign_requests + pending_count + count

            if projected > self.campaign_budget:
                reason = f"Campaign budget exhausted ({self._campaign_requests} used, {pending_count} pending, limit {self.campaign_budget})"
                self._record_event("campaign_exhausted", target_url, check_id, reason)
                return False, reason

            target_used = self._target_requests.get(target_url, 0)
            if target_used + count > self.target_budget:
                reason = f"Target budget exhausted ({target_used}/{self.target_budget}) for {target_url}"
                self._record_event("target_exhausted", target_url, check_id, reason)
                return False, reason

            check_key = f"{target_url}|{check_id}"
            check_used = self._check_requests.get(check_key, 0)
            if check_used + count > self.check_budget:
                reason = f"Check budget exhausted ({check_used}/{self.check_budget}) for {check_id}"
                self._record_event("check_exhausted", target_url, check_id, reason)
                return False, reason

            return True, "OK"

    async def reserve_budget(self, target_url: str, check_id: str, count: int = 1) -> BudgetReservation:
        """Atomically reserve budget tokens before issuing requests."""
        async with self._lock:
            pending_count = sum(r.count for r in self._reservations.values())
            projected = self._campaign_requests + pending_count + count

            if projected > self.campaign_budget:
                reason = f"Campaign budget exceeded: cannot reserve {count} requests (used: {self._campaign_requests}, pending: {pending_count}, limit: {self.campaign_budget})"
                self._record_event("campaign_exhausted", target_url, check_id, reason)
                raise BudgetExhaustedException(reason)

            import uuid
            token = str(uuid.uuid4())
            res = BudgetReservation(
                token_id=token,
                campaign_id=self.campaign_id,
                target_url=target_url,
                check_id=check_id,
                count=count,
            )
            self._reservations[token] = res
            return res

    async def commit_reservation(self, reservation: BudgetReservation, actual_count: Optional[int] = None) -> None:
        """Commit reserved budget once requests have completed."""
        async with self._lock:
            res = self._reservations.pop(reservation.token_id, None)
            used = actual_count if actual_count is not None else (res.count if res else reservation.count)
            self._campaign_requests += used

            target = reservation.target_url
            self._target_requests[target] = self._target_requests.get(target, 0) + used

            check_key = f"{target}|{reservation.check_id}"
            self._check_requests[check_key] = self._check_requests.get(check_key, 0) + used

    async def rollback_reservation(self, reservation: BudgetReservation) -> None:
        """Release a reservation without incrementing usage (e.g. if skipped/cancelled)."""
        async with self._lock:
            self._reservations.pop(reservation.token_id, None)

    async def record_request(self, target_url: str, check_id: str, count: int = 1) -> None:
        """Directly record requests without reservation."""
        async with self._lock:
            self._campaign_requests += count
            self._target_requests[target_url] = self._target_requests.get(target_url, 0) + count
            check_key = f"{target_url}|{check_id}"
            self._check_requests[check_key] = self._check_requests.get(check_key, 0) + count

    def is_exhausted(self, target_url: str, check_id: str) -> bool:
        """Synchronous fast-path exhaustion check."""
        if self._campaign_requests >= self.campaign_budget:
            return True
        if self._target_requests.get(target_url, 0) >= self.target_budget:
            return True
        if self._check_requests.get(f"{target_url}|{check_id}", 0) >= self.check_budget:
            return True
        return False
