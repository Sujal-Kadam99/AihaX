"""AihaX Phase 8 — Structured Operational Metrics Collector.

Collects bounded, low-cardinality operational metrics across campaigns, tasks,
network requests, findings, evidence, and coverage.

Invariants:
- Never includes high-cardinality labels (URLs, parameters, tokens, user IDs, raw payloads).
- Low-overhead in-memory counters with export functions.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict

logger = logging.getLogger(__name__)


@dataclass
class OperationalMetricsSnapshot:
    # Campaign counters
    campaigns_total: int = 0
    campaigns_running: int = 0
    campaigns_completed: int = 0
    campaigns_failed: int = 0
    campaigns_paused: int = 0
    campaigns_cancelled: int = 0

    # Task counters
    tasks_total: int = 0
    tasks_pending: int = 0
    tasks_claimed: int = 0
    tasks_running: int = 0
    tasks_completed: int = 0
    tasks_failed: int = 0
    tasks_retried: int = 0
    tasks_recovered_stale: int = 0

    # Network request counters
    requests_total: int = 0
    requests_blocked_scope: int = 0
    requests_blocked_budget: int = 0
    requests_failed: int = 0

    # Finding counters
    findings_candidates: int = 0
    findings_verified: int = 0
    findings_reportable: int = 0
    findings_blocked: int = 0

    # Evidence Vault counters
    evidence_created: int = 0
    evidence_integrity_failures: int = 0

    # Coverage counters
    coverage_checks_executed: int = 0
    coverage_checks_skipped: int = 0

    collected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MetricsCollector:
    """Singleton/Instance metrics collector tracking operational activity."""

    _instance: Optional[MetricsCollector] = None

    def __init__(self) -> None:
        self._metrics = OperationalMetricsSnapshot()

    @classmethod
    def get_instance(cls) -> MetricsCollector:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # Campaign lifecycle increments
    def record_campaign_created(self) -> None:
        self._metrics.campaigns_total += 1

    def record_campaign_started(self) -> None:
        self._metrics.campaigns_running += 1

    def record_campaign_completed(self) -> None:
        self._metrics.campaigns_running = max(0, self._metrics.campaigns_running - 1)
        self._metrics.campaigns_completed += 1

    def record_campaign_failed(self) -> None:
        self._metrics.campaigns_running = max(0, self._metrics.campaigns_running - 1)
        self._metrics.campaigns_failed += 1

    def record_campaign_paused(self) -> None:
        self._metrics.campaigns_running = max(0, self._metrics.campaigns_running - 1)
        self._metrics.campaigns_paused += 1

    def record_campaign_cancelled(self) -> None:
        self._metrics.campaigns_running = max(0, self._metrics.campaigns_running - 1)
        self._metrics.campaigns_cancelled += 1

    # Task increments
    def record_tasks_created(self, count: int = 1) -> None:
        self._metrics.tasks_total += count
        self._metrics.tasks_pending += count

    def record_task_claimed(self, count: int = 1) -> None:
        self._metrics.tasks_pending = max(0, self._metrics.tasks_pending - count)
        self._metrics.tasks_claimed += count

    def record_task_running(self, count: int = 1) -> None:
        self._metrics.tasks_claimed = max(0, self._metrics.tasks_claimed - count)
        self._metrics.tasks_running += count

    def record_task_completed(self, count: int = 1) -> None:
        self._metrics.tasks_running = max(0, self._metrics.tasks_running - count)
        self._metrics.tasks_completed += count

    def record_task_failed(self, count: int = 1) -> None:
        self._metrics.tasks_running = max(0, self._metrics.tasks_running - count)
        self._metrics.tasks_failed += count

    def record_task_retried(self, count: int = 1) -> None:
        self._metrics.tasks_running = max(0, self._metrics.tasks_running - count)
        self._metrics.tasks_retried += count
        self._metrics.tasks_pending += count

    def record_stale_task_recovered(self, count: int = 1) -> None:
        self._metrics.tasks_recovered_stale += count

    # Network increments
    def record_request_issued(self, count: int = 1) -> None:
        self._metrics.requests_total += count

    def record_request_blocked_scope(self, count: int = 1) -> None:
        self._metrics.requests_blocked_scope += count

    def record_request_blocked_budget(self, count: int = 1) -> None:
        self._metrics.requests_blocked_budget += count

    def record_request_failed(self, count: int = 1) -> None:
        self._metrics.requests_failed += count

    # Finding increments
    def record_finding_candidate(self, count: int = 1) -> None:
        self._metrics.findings_candidates += count

    def record_finding_verified(self, count: int = 1) -> None:
        self._metrics.findings_verified += count

    def record_finding_reportable(self, count: int = 1) -> None:
        self._metrics.findings_reportable += count

    def record_finding_blocked(self, count: int = 1) -> None:
        self._metrics.findings_blocked += count

    # Evidence increments
    def record_evidence_created(self, count: int = 1) -> None:
        self._metrics.evidence_created += count

    def record_evidence_integrity_failure(self, count: int = 1) -> None:
        self._metrics.evidence_integrity_failures += count

    # Coverage increments
    def record_coverage_executed(self, count: int = 1) -> None:
        self._metrics.coverage_checks_executed += count

    def record_coverage_skipped(self, count: int = 1) -> None:
        self._metrics.coverage_checks_skipped += count

    def get_snapshot(self) -> OperationalMetricsSnapshot:
        self._metrics.collected_at = datetime.now(timezone.utc).isoformat()
        return self._metrics

    def reset(self) -> None:
        self._metrics = OperationalMetricsSnapshot()


metrics = MetricsCollector.get_instance()
