"""AihaX Phase 8 — Persistent Campaign Repository.

Provides transactional operations for:
- Campaign lifecycle persistence & state transitions
- Atomic task lease acquisition & stale worker recovery
- Authorization record management
- Evidence record persistence & retrieval
- Tamper-evident chained audit event logging
- Immutable configuration snapshot storage
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import Session

from backend.persistence.models import (
    AuditTrailEvent,
    AuthorizationRecord,
    Campaign,
    CampaignSnapshot,
    CampaignTarget,
    EvidenceRecord,
    ExecutionTask,
)
from backend.persistence.state_machine import (
    CampaignLifecycleState,
    CampaignStateMachine,
    InvalidStateTransitionError,
    TaskLifecycleState,
    TaskStateMachine,
)

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _compute_event_hash(
    campaign_id: str,
    event_type: str,
    actor: str,
    timestamp_str: str,
    metadata_json: Optional[str],
    previous_hash: Optional[str],
) -> str:
    """Compute SHA-256 hash for tamper-evident audit log chaining."""
    raw = f"{campaign_id}|{event_type}|{actor}|{timestamp_str}|{metadata_json or ''}|{previous_hash or 'GENESIS'}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class CampaignRepository:
    """Transactional repository managing persistent campaigns, tasks, evidence, and audit logs."""

    def __init__(self, session: Session) -> None:
        self.session = session

    # ──────────────────────────────────────────────────────────────────────────
    # 1. CAMPAIGN LIFECYCLE
    # ──────────────────────────────────────────────────────────────────────────

    def create_campaign(
        self,
        name: str,
        target_url: str,
        mode: str = "SAFE_SCAN",
        campaign_budget: int = 500,
        target_budget: int = 100,
        check_budget: int = 20,
        max_concurrency: int = 5,
        rate_limit_rps: int = 10,
        program_id: Optional[str] = None,
        user_id: Optional[str] = None,
        campaign_id: Optional[str] = None,
    ) -> Campaign:
        if not target_url or not isinstance(target_url, str) or "*" in target_url:
            raise ValueError("Wildcard scope rules cannot be used as executable assessment targets. Enter a concrete host.")
        cid = campaign_id or str(uuid.uuid4())
        campaign = Campaign(
            id=cid,
            name=name,
            target_url=target_url,
            mode=mode,
            status=CampaignLifecycleState.DRAFT.value,
            program_id=program_id,
            user_id=user_id,
            created_at=_utc_now(),
            campaign_budget=campaign_budget,
            target_budget=target_budget,
            check_budget=check_budget,
            max_concurrency=max_concurrency,
            rate_limit_rps=rate_limit_rps,
            requests_used=0,
        )
        self.session.add(campaign)
        self.session.flush()

        self.append_audit_event(
            campaign_id=cid,
            event_type="campaign_created",
            actor=user_id or "system",
            object_id=cid,
            metadata={"name": name, "target_url": target_url, "mode": mode, "budget": campaign_budget},
        )
        return campaign

    def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        return self.session.query(Campaign).filter(Campaign.id == campaign_id).first()

    def list_campaigns(
        self,
        user_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Campaign]:
        query = self.session.query(Campaign)
        if user_id:
            query = query.filter(Campaign.user_id == user_id)
        if status:
            query = query.filter(Campaign.status == status)
        return query.order_by(Campaign.created_at.desc()).offset(offset).limit(limit).all()

    def update_campaign_status(
        self,
        campaign_id: str,
        target_status: str | CampaignLifecycleState,
        actor: str = "system",
        reason: Optional[str] = None,
    ) -> Campaign:
        campaign = self.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")

        target_enum = CampaignStateMachine.transition_or_raise(campaign.status, target_status)
        old_status = campaign.status
        campaign.status = target_enum.value
        now = _utc_now()

        if target_enum == CampaignLifecycleState.RUNNING:
            if not campaign.started_at:
                campaign.started_at = now
        elif target_enum == CampaignLifecycleState.PAUSED:
            campaign.paused_at = now
        elif target_enum in (CampaignLifecycleState.COMPLETED, CampaignLifecycleState.FAILED, CampaignLifecycleState.CANCELLED):
            campaign.completed_at = now

        self.session.flush()

        self.append_audit_event(
            campaign_id=campaign_id,
            event_type=f"campaign_{target_enum.value.lower()}",
            actor=actor,
            object_id=campaign_id,
            metadata={"old_status": old_status, "new_status": target_enum.value, "reason": reason or ""},
        )
        return campaign

    def set_campaign_hashes(
        self,
        campaign_id: str,
        scope_snapshot_hash: Optional[str] = None,
        config_hash: Optional[str] = None,
        registry_hash: Optional[str] = None,
        manifest_hash: Optional[str] = None,
    ) -> Campaign:
        campaign = self.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")
        if scope_snapshot_hash:
            campaign.scope_snapshot_hash = scope_snapshot_hash
        if config_hash:
            campaign.config_hash = config_hash
        if registry_hash:
            campaign.registry_hash = registry_hash
        if manifest_hash:
            campaign.manifest_hash = manifest_hash
        self.session.flush()
        return campaign

    def increment_requests_used(self, campaign_id: str, count: int = 1) -> int:
        campaign = self.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")
        campaign.requests_used += count
        self.session.flush()
        return campaign.requests_used

    # ──────────────────────────────────────────────────────────────────────────
    # 2. AUTHORIZATION RECORD
    # ──────────────────────────────────────────────────────────────────────────

    def create_authorization(
        self,
        campaign_id: str,
        authorized_by: str,
        scope_hash: str,
        authorization_type: str = "explicit_scope_consent",
        authorization_reference: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> AuthorizationRecord:
        auth_record = AuthorizationRecord(
            id=str(uuid.uuid4()),
            campaign_id=campaign_id,
            authorized_by=authorized_by,
            authorization_type=authorization_type,
            authorization_reference=authorization_reference,
            authorized_at=_utc_now(),
            expires_at=expires_at or (_utc_now() + timedelta(days=30)),
            scope_hash=scope_hash,
            status="ACTIVE",
        )
        self.session.add(auth_record)
        self.session.flush()

        self.append_audit_event(
            campaign_id=campaign_id,
            event_type="campaign_authorized",
            actor=authorized_by,
            object_id=auth_record.id,
            metadata={"authorization_type": authorization_type, "scope_hash": scope_hash},
        )
        return auth_record

    def get_authorization(self, campaign_id: str) -> Optional[AuthorizationRecord]:
        return self.session.query(AuthorizationRecord).filter(AuthorizationRecord.campaign_id == campaign_id).first()

    # ──────────────────────────────────────────────────────────────────────────
    # 3. TARGETS
    # ──────────────────────────────────────────────────────────────────────────

    def add_target(
        self,
        campaign_id: str,
        normalized_url: str,
        scope_status: str = "IN_SCOPE",
    ) -> CampaignTarget:
        if not normalized_url or not isinstance(normalized_url, str) or "*" in normalized_url:
            raise ValueError("Wildcard scope rules cannot be added as concrete CampaignTarget records.")

        existing = (
            self.session.query(CampaignTarget)
            .filter(CampaignTarget.campaign_id == campaign_id, CampaignTarget.normalized_url == normalized_url)
            .first()
        )
        if existing:
            return existing

        target = CampaignTarget(
            id=str(uuid.uuid4()),
            campaign_id=campaign_id,
            normalized_url=normalized_url,
            scope_status=scope_status,
            auth_status="PENDING",
            target_status="PENDING",
            recon_status="PENDING",
            execution_status="PENDING",
            requests_used=0,
            created_at=_utc_now(),
        )
        self.session.add(target)
        self.session.flush()
        return target

    def get_targets(self, campaign_id: str) -> List[CampaignTarget]:
        return self.session.query(CampaignTarget).filter(CampaignTarget.campaign_id == campaign_id).all()

    def release_campaign_targets(self, campaign_id: str) -> List[CampaignTarget]:
        """Release target assignments for a cancelled/completed campaign."""
        targets = self.get_targets(campaign_id)
        for t in targets:
            t.target_status = "RELEASED"
            t.execution_status = "CANCELLED"
        self.session.flush()
        return targets

    # ──────────────────────────────────────────────────────────────────────────
    # 4. TASK QUEUE & ATOMIC LEASES
    # ──────────────────────────────────────────────────────────────────────────

    def create_task(
        self,
        campaign_id: str,
        target_url: str,
        check_id: str,
        endpoint_url: str,
        parameter_name: Optional[str] = None,
        target_id: Optional[str] = None,
        budget_reservation: int = 1,
        idempotency_key: Optional[str] = None,
    ) -> ExecutionTask:
        if not target_url or not isinstance(target_url, str) or "*" in target_url:
            raise ValueError("Wildcard scope rules cannot be used as ExecutionTask targets.")
        if not endpoint_url or not isinstance(endpoint_url, str) or "*" in endpoint_url:
            raise ValueError("Wildcard scope rules cannot be used as ExecutionTask endpoint URLs.")

        campaign = self.get_campaign(campaign_id)
        if campaign and campaign.status in (
            CampaignLifecycleState.CANCELLED.value,
            CampaignLifecycleState.COMPLETED.value,
            CampaignLifecycleState.FAILED.value,
        ):
            raise InvalidStateTransitionError(
                "ExecutionTask",
                "NONE",
                "PENDING",
                f"Cannot create task for terminal campaign in '{campaign.status}' state.",
            )

        key = idempotency_key or f"{campaign_id}|{check_id}|{endpoint_url}|{parameter_name or 'GLOBAL'}"
        existing = self.session.query(ExecutionTask).filter(ExecutionTask.idempotency_key == key).first()
        if existing:
            return existing

        task = ExecutionTask(
            id=str(uuid.uuid4()),
            campaign_id=campaign_id,
            target_id=target_id,
            target_url=target_url,
            check_id=check_id,
            endpoint_url=endpoint_url,
            parameter_name=parameter_name,
            status=TaskLifecycleState.PENDING.value,
            attempt_count=0,
            max_retries=3,
            budget_reservation=budget_reservation,
            created_at=_utc_now(),
            idempotency_key=key,
        )
        self.session.add(task)
        self.session.flush()
        return task

    def create_tasks_batch(self, campaign_id: str, task_specs: List[Dict[str, Any]]) -> List[ExecutionTask]:
        campaign = self.get_campaign(campaign_id)
        if campaign and campaign.status in (
            CampaignLifecycleState.CANCELLED.value,
            CampaignLifecycleState.COMPLETED.value,
            CampaignLifecycleState.FAILED.value,
        ):
            raise InvalidStateTransitionError(
                "ExecutionTask",
                "NONE",
                "PENDING",
                f"Cannot create tasks batch for terminal campaign in '{campaign.status}' state.",
            )

        created: List[ExecutionTask] = []
        for spec in task_specs:
            t = self.create_task(
                campaign_id=campaign_id,
                target_url=spec["target_url"],
                check_id=spec["check_id"],
                endpoint_url=spec["endpoint_url"],
                parameter_name=spec.get("parameter_name"),
                target_id=spec.get("target_id"),
                budget_reservation=spec.get("budget_reservation", 1),
                idempotency_key=spec.get("idempotency_key"),
            )
            created.append(t)
        return created

    def claim_tasks(
        self,
        campaign_id: str,
        worker_id: str,
        limit: int = 5,
        lease_duration_seconds: int = 60,
    ) -> List[ExecutionTask]:
        """Atomically claim pending or retry-pending tasks under worker lease."""
        campaign = self.get_campaign(campaign_id)
        if campaign and campaign.status in (
            CampaignLifecycleState.CANCELLED.value,
            CampaignLifecycleState.COMPLETED.value,
            CampaignLifecycleState.FAILED.value,
        ):
            return []

        now = _utc_now()
        lease_expires = now + timedelta(seconds=lease_duration_seconds)

        # Select tasks that are PENDING or RETRY_PENDING
        candidate_tasks = (
            self.session.query(ExecutionTask)
            .filter(
                ExecutionTask.campaign_id == campaign_id,
                ExecutionTask.status.in_([TaskLifecycleState.PENDING.value, TaskLifecycleState.RETRY_PENDING.value]),
            )
            .order_by(ExecutionTask.created_at.asc())
            .limit(limit)
            .all()
        )

        claimed: List[ExecutionTask] = []
        for task in candidate_tasks:
            TaskStateMachine.transition_or_raise(task.status, TaskLifecycleState.CLAIMED)
            task.status = TaskLifecycleState.CLAIMED.value
            task.worker_id = worker_id
            task.lease_expires_at = lease_expires
            task.attempt_count += 1
            task.started_at = now
            claimed.append(task)

        self.session.flush()

        for t in claimed:
            self.append_audit_event(
                campaign_id=campaign_id,
                event_type="task_claimed",
                actor=worker_id,
                object_id=t.id,
                metadata={"check_id": t.check_id, "endpoint_url": t.endpoint_url, "attempt": t.attempt_count},
            )
        return claimed

    def renew_task_lease(self, task_id: str, worker_id: str, lease_duration_seconds: int = 60) -> bool:
        now = _utc_now()
        task = self.session.query(ExecutionTask).filter(ExecutionTask.id == task_id, ExecutionTask.worker_id == worker_id).first()
        if not task:
            return False
        task.lease_expires_at = now + timedelta(seconds=lease_duration_seconds)
        self.session.flush()
        return True

    def complete_task(self, task_id: str, worker_id: str) -> ExecutionTask:
        task = self.session.query(ExecutionTask).filter(ExecutionTask.id == task_id).first()
        if not task:
            raise ValueError(f"Task '{task_id}' not found.")
        if task.status == TaskLifecycleState.COMPLETED.value:
            return task
        if task.worker_id and task.worker_id != worker_id:
            raise ValueError(f"Worker '{worker_id}' does not own task '{task_id}' (owned by '{task.worker_id}').")
        TaskStateMachine.transition_or_raise(task.status, TaskLifecycleState.COMPLETED)
        task.status = TaskLifecycleState.COMPLETED.value
        task.completed_at = _utc_now()
        task.lease_expires_at = None
        self.session.flush()

        self.append_audit_event(
            campaign_id=task.campaign_id,
            event_type="task_completed",
            actor=worker_id,
            object_id=task.id,
            metadata={"check_id": task.check_id, "endpoint_url": task.endpoint_url},
        )
        return task

    def fail_task(self, task_id: str, worker_id: str, reason: str, can_retry: bool = True) -> ExecutionTask:
        task = self.session.query(ExecutionTask).filter(ExecutionTask.id == task_id).first()
        if not task:
            raise ValueError(f"Task '{task_id}' not found.")
        if task.worker_id and task.worker_id != worker_id:
            raise ValueError(f"Worker '{worker_id}' does not own task '{task_id}' (owned by '{task.worker_id}').")

        task.failure_reason = reason
        task.lease_expires_at = None

        if can_retry and task.attempt_count < task.max_retries:
            TaskStateMachine.transition_or_raise(task.status, TaskLifecycleState.RETRY_PENDING)
            task.status = TaskLifecycleState.RETRY_PENDING.value
            event_name = "task_retry_scheduled"
        else:
            TaskStateMachine.transition_or_raise(task.status, TaskLifecycleState.FAILED)
            task.status = TaskLifecycleState.FAILED.value
            task.completed_at = _utc_now()
            event_name = "task_failed"

        self.session.flush()
        self.append_audit_event(
            campaign_id=task.campaign_id,
            event_type=event_name,
            actor=worker_id,
            object_id=task.id,
            metadata={"reason": reason, "attempt": task.attempt_count, "max_retries": task.max_retries},
        )
        return task

    def recover_stale_tasks(self, campaign_id: Optional[str] = None) -> List[ExecutionTask]:
        """Recovers tasks whose worker lease has expired while CLAIMED or RUNNING (never resurrects cancelled campaigns)."""
        now = _utc_now()
        query = (
            self.session.query(ExecutionTask)
            .join(Campaign, ExecutionTask.campaign_id == Campaign.id)
            .filter(
                Campaign.status.notin_([
                    CampaignLifecycleState.CANCELLED.value,
                    CampaignLifecycleState.COMPLETED.value,
                    CampaignLifecycleState.FAILED.value,
                ]),
                ExecutionTask.status.in_([TaskLifecycleState.CLAIMED.value, TaskLifecycleState.RUNNING.value]),
                ExecutionTask.lease_expires_at < now,
            )
        )
        if campaign_id:
            campaign = self.get_campaign(campaign_id)
            if not campaign or campaign.status in (
                CampaignLifecycleState.CANCELLED.value,
                CampaignLifecycleState.COMPLETED.value,
                CampaignLifecycleState.FAILED.value,
            ):
                return []
            query = query.filter(ExecutionTask.campaign_id == campaign_id)

        stale_tasks = query.all()
        recovered: List[ExecutionTask] = []

        for task in stale_tasks:
            task.worker_id = None
            task.lease_expires_at = None
            if task.attempt_count < task.max_retries:
                task.status = TaskLifecycleState.RETRY_PENDING.value
            else:
                task.status = TaskLifecycleState.FAILED.value
                task.failure_reason = "Worker lease expired and maximum retries exceeded."
                task.completed_at = now
            recovered.append(task)

            self.append_audit_event(
                campaign_id=task.campaign_id,
                event_type="stale_task_recovered",
                actor="system_recovery",
                object_id=task.id,
                metadata={"new_status": task.status, "attempts": task.attempt_count},
            )

        self.session.flush()
        return recovered

    def count_tasks_by_status(self, campaign_id: str) -> Dict[str, int]:
        tasks = self.session.query(ExecutionTask).filter(ExecutionTask.campaign_id == campaign_id).all()
        counts: Dict[str, int] = {}
        for t in tasks:
            counts[t.status] = counts.get(t.status, 0) + 1
        return counts

    # ──────────────────────────────────────────────────────────────────────────
    # 5. EVIDENCE RECORDS (EVIDENCE VAULT)
    # ──────────────────────────────────────────────────────────────────────────

    def record_evidence(
        self,
        campaign_id: str,
        evidence_type: str,
        target_url: str,
        content_hash: str,
        method: str = "GET",
        sanitized_request: Optional[str] = None,
        sanitized_response: Optional[str] = None,
        payload_summary: Optional[str] = None,
        chain_hash: Optional[str] = None,
        finding_id: Optional[str] = None,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        evidence_id: Optional[str] = None,
    ) -> EvidenceRecord:
        if task_id:
            existing = (
                self.session.query(EvidenceRecord)
                .filter(
                    EvidenceRecord.campaign_id == campaign_id,
                    EvidenceRecord.content_hash == content_hash,
                    EvidenceRecord.task_id == task_id,
                )
                .first()
            )
            if existing:
                return existing

        eid = evidence_id or str(uuid.uuid4())
        record = EvidenceRecord(
            id=eid,
            campaign_id=campaign_id,
            finding_id=finding_id,
            task_id=task_id,
            request_id=request_id,
            evidence_type=evidence_type,
            target_url=target_url,
            method=method,
            sanitized_request=sanitized_request,
            sanitized_response=sanitized_response,
            payload_summary=payload_summary,
            content_hash=content_hash,
            chain_hash=chain_hash,
            created_at=_utc_now(),
        )
        self.session.add(record)
        self.session.flush()

        self.append_audit_event(
            campaign_id=campaign_id,
            event_type="evidence_created",
            actor="evidence_vault",
            object_id=eid,
            metadata={"evidence_type": evidence_type, "content_hash": content_hash, "finding_id": finding_id},
        )
        return record

    def get_evidence_for_campaign(
        self,
        campaign_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> List[EvidenceRecord]:
        return (
            self.session.query(EvidenceRecord)
            .filter(EvidenceRecord.campaign_id == campaign_id)
            .order_by(EvidenceRecord.created_at.asc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    def get_evidence_by_id(self, evidence_id: str) -> Optional[EvidenceRecord]:
        return self.session.query(EvidenceRecord).filter(EvidenceRecord.id == evidence_id).first()

    # Aliases for compatibility
    store_evidence_record = record_evidence
    get_evidence_record = get_evidence_by_id

    # ──────────────────────────────────────────────────────────────────────────
    # 6. TAMPER-EVIDENT AUDIT TRAIL
    # ──────────────────────────────────────────────────────────────────────────

    def append_audit_event(
        self,
        campaign_id: str,
        event_type: str,
        actor: str = "system",
        object_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditTrailEvent:
        now = _utc_now()
        now_str = now.isoformat()
        meta_str = json.dumps(metadata or {}, sort_keys=True)

        # Retrieve previous event hash for chaining
        last_event = (
            self.session.query(AuditTrailEvent)
            .filter(AuditTrailEvent.campaign_id == campaign_id)
            .order_by(AuditTrailEvent.timestamp.desc())
            .first()
        )
        prev_hash = last_event.event_hash if last_event else None

        event_hash = _compute_event_hash(
            campaign_id=campaign_id,
            event_type=event_type,
            actor=actor,
            timestamp_str=now_str,
            metadata_json=meta_str,
            previous_hash=prev_hash,
        )

        event = AuditTrailEvent(
            id=str(uuid.uuid4()),
            campaign_id=campaign_id,
            timestamp=now,
            actor=actor,
            event_type=event_type,
            object_id=object_id,
            metadata_json=meta_str,
            previous_event_hash=prev_hash,
            event_hash=event_hash,
        )
        self.session.add(event)
        self.session.flush()
        return event

    def get_audit_trail(self, campaign_id: str) -> List[AuditTrailEvent]:
        return (
            self.session.query(AuditTrailEvent)
            .filter(AuditTrailEvent.campaign_id == campaign_id)
            .order_by(AuditTrailEvent.timestamp.asc())
            .all()
        )

    # Alias for compatibility
    get_audit_events = get_audit_trail

    def verify_audit_trail_integrity(self, campaign_id: str) -> bool:
        """Verify the cryptographic SHA-256 hash chaining of audit events for a campaign."""
        events = self.get_audit_trail(campaign_id)
        if not events:
            return True

        prev_hash = None
        for event in events:
            if event.previous_event_hash != prev_hash:
                return False
            ts_str = event.timestamp.isoformat() if hasattr(event.timestamp, "isoformat") else str(event.timestamp)
            expected_hash = _compute_event_hash(
                campaign_id=event.campaign_id,
                event_type=event.event_type,
                actor=event.actor,
                timestamp_str=ts_str,
                metadata_json=event.metadata_json or "{}",
                previous_hash=prev_hash,
            )
            if event.event_hash != expected_hash:
                return False
            prev_hash = event.event_hash
        return True

    # ──────────────────────────────────────────────────────────────────────────
    # 7. SNAPSHOTS
    # ──────────────────────────────────────────────────────────────────────────

    def save_snapshot(self, campaign_id: str, snapshot_data: Dict[str, Any]) -> CampaignSnapshot:
        data_json = json.dumps(snapshot_data, sort_keys=True)
        snap_hash = hashlib.sha256(data_json.encode("utf-8")).hexdigest()

        existing = self.session.query(CampaignSnapshot).filter(CampaignSnapshot.campaign_id == campaign_id).first()
        if existing:
            existing.snapshot_json = data_json
            existing.snapshot_hash = snap_hash
            self.session.flush()
            return existing

        snap = CampaignSnapshot(
            id=str(uuid.uuid4()),
            campaign_id=campaign_id,
            snapshot_json=data_json,
            snapshot_hash=snap_hash,
            created_at=_utc_now(),
        )
        self.session.add(snap)
        self.session.flush()
        return snap

    def get_snapshot(self, campaign_id: str) -> Optional[CampaignSnapshot]:
        return self.session.query(CampaignSnapshot).filter(CampaignSnapshot.campaign_id == campaign_id).first()
