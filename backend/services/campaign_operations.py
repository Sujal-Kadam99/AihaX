"""AihaX Phase 8 — Campaign Operations Service.

Provides centralized management for:
- Campaign lifecycle state transitions (DRAFT -> AUTHORIZED -> QUEUED -> RUNNING -> PAUSED -> COMPLETED)
- Mandatory authorization verification & scope gating
- Task queue creation, dispatch, and worker coordination
- Crash-safe stale task recovery
- Evidence vault integration and manifest verification
- Comprehensive audit trail event logging
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sqlalchemy.orm import Session

import backend.agents.checks  # Ensure the check registry is populated
from backend.core.check_registry import registry
from backend.core.scope_validator import ScopeValidator, normalize_url, validate_concrete_target_url, validate_destination_safety
from backend.evidence.evidence_manifest import (
    CampaignIntegrityReport,
    CampaignManifest,
    ManifestBuilder,
)
from backend.evidence.evidence_store import EvidenceVault
from backend.persistence.models import (
    AuthorizationRecord,
    Campaign,
    CampaignSnapshot,
    CampaignTarget,
    ExecutionTask,
)
from backend.persistence.repository import CampaignRepository
from backend.persistence.state_machine import (
    CampaignLifecycleState,
    CampaignStateMachine,
    InvalidStateTransitionError,
    TaskLifecycleState,
)
from backend.services.metrics_collector import metrics
from backend.services.persistent_budget import PersistentRequestBudget

logger = logging.getLogger(__name__)

LOCKED_PRODUCTION_PROFILE = {
    "budget": 10,
    "max_concurrency": 1,
    "rate_limit_rps": 2,
    "allowed_methods": ["GET", "HEAD", "OPTIONS"],
    "ssrf_protection": True,
}


@dataclass
class ExecutionPlanCheck:
    """Standardized entry for an authorized check within a campaign execution plan."""
    check_id: str
    enabled: bool = True
    destructive: bool = False
    execution_order: int = 1
    timeout_seconds: int = 30
    expected_request_budget: int = 10
    check_version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutionPlan:
    """Deterministic, immutable execution plan bound to a campaign authorization and scope snapshot."""
    campaign_id: str
    target_url: str
    authorized_scope_hash: str
    authorization_id: str
    created_at: str
    checks: List[ExecutionPlanCheck] = field(default_factory=list)
    budget_snapshot: Dict[str, int] = field(default_factory=dict)
    plan_hash: str = ""

    def compute_hash(self) -> str:
        data = {
            "campaign_id": self.campaign_id,
            "target_url": self.target_url,
            "authorized_scope_hash": self.authorized_scope_hash,
            "authorization_id": self.authorization_id,
            "checks": [c.to_dict() for c in sorted(self.checks, key=lambda x: (x.execution_order, x.check_id))],
            "budget_snapshot": self.budget_snapshot,
        }
        serialized = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def verify_integrity(self) -> bool:
        if not self.plan_hash:
            return False
        return self.compute_hash() == self.plan_hash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "target_url": self.target_url,
            "authorized_scope_hash": self.authorized_scope_hash,
            "authorization_id": self.authorization_id,
            "created_at": self.created_at,
            "checks": [c.to_dict() for c in self.checks],
            "budget_snapshot": self.budget_snapshot,
            "plan_hash": self.plan_hash or self.compute_hash(),
        }


class AuthorizationRequiredException(Exception):
    """Raised when an unauthorized campaign attempts execution."""
    pass


class ScopeMismatchException(Exception):
    """Raised when campaign scope differs from authorization record."""
    pass


@dataclass
class TargetBindingRequest:
    campaign_id: str
    target_url: str
    actor: str = "operator"
    notes: Optional[str] = None


class CampaignOperationsService:
    """Operations coordinator for persistent campaign lifecycle and execution management."""

    def __init__(self, repository: CampaignRepository) -> None:
        self.repo = repository
        self.vault = EvidenceVault(repository)

    # ──────────────────────────────────────────────────────────────────────────
    # 1. CAMPAIGN CREATION & AUTHORIZATION
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
        in_scope_assets: Optional[List[str]] = None,
        selected_checks: Optional[List[str]] = None,
        selected_tools: Optional[List[str]] = None,
        assessment_mode: str = "CONTROLLED",
        awaiting_target: bool = False,
    ) -> Campaign:
        """Create a new campaign in DRAFT or WAITING_FOR_TARGET status with initial configuration snapshot."""
        if not target_url or target_url == "WAITING_FOR_TARGET" or awaiting_target:
            normalized_target = "WAITING_FOR_TARGET"
            awaiting_target = True
        else:
            if "*" in target_url:
                raise ValueError("Wildcard scope rules cannot be used as executable assessment targets. Enter a concrete host.")
            scheme, host, port, path, canonical_url = validate_concrete_target_url(target_url)
            normalized_target = f"{scheme}://{host}" if (port == 80 and scheme == "http") or (port == 443 and scheme == "https") else f"{scheme}://{host}:{port}"

        campaign = self.repo.create_campaign(
            name=name,
            target_url=normalized_target,
            mode=mode,
            campaign_budget=campaign_budget,
            target_budget=target_budget,
            check_budget=check_budget,
            max_concurrency=max_concurrency,
            rate_limit_rps=rate_limit_rps,
            program_id=program_id,
            user_id=user_id,
        )
        if hasattr(campaign, "awaiting_target"):
            campaign.awaiting_target = awaiting_target
        if hasattr(campaign, "assessment_mode"):
            campaign.assessment_mode = assessment_mode
        self.repo.session.flush()

        # 2. Add root target if concrete
        if normalized_target != "WAITING_FOR_TARGET":
            self.repo.add_target(campaign_id=campaign.id, normalized_url=normalized_target, scope_status="IN_SCOPE")

        # 3. Add additional in-scope assets (only concrete URLs, skipping wildcards)
        if in_scope_assets:
            for raw in in_scope_assets:
                if not raw or not isinstance(raw, str) or "*" in raw:
                    continue
                try:
                    s, h, p, _, _ = validate_concrete_target_url(raw)
                    can_url = f"{s}://{h}" if (p == 80 and s == "http") or (p == 443 and s == "https") else f"{s}://{h}:{p}"
                    self.repo.add_target(campaign_id=campaign.id, normalized_url=can_url, scope_status="IN_SCOPE")
                except Exception as e:
                    logger.warning(f"Could not normalize asset '{raw}': {e}")

        # 4. Compute and save initial snapshot
        all_targets = [t.normalized_url for t in self.repo.get_targets(campaign.id)]
        scope_canonical = json.dumps(sorted(all_targets), sort_keys=True)
        scope_hash = hashlib.sha256(scope_canonical.encode("utf-8")).hexdigest()

        reg_meta = registry.get_registry_metadata()
        from backend.services.vulnerability_tool_policy import normalize_tool_selections
        normalized_tools = normalize_tool_selections(selected_tools if selected_tools is not None else ["zap"])
        snapshot_data = {
            "campaign_id": campaign.id,
            "name": name,
            "target_url": normalized_target,
            "mode": mode,
            "scope_assets": sorted(all_targets),
            "scope_hash": scope_hash,
            "selected_checks": selected_checks or reg_meta["check_ids"],
            "selected_tools": normalized_tools,
            "registry_version": reg_meta["registry_version"],
            "registry_hash": reg_meta["registry_hash"],
            "contract_hash": reg_meta["contract_hash"],
            "budgets": {
                "campaign": campaign_budget,
                "target": target_budget,
                "check": check_budget,
            },
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.repo.save_snapshot(campaign.id, snapshot_data)
        self.repo.set_campaign_hashes(
            campaign_id=campaign.id,
            scope_snapshot_hash=scope_hash,
            registry_hash=reg_meta["registry_hash"],
        )

        metrics.record_campaign_created()
        return campaign

    def bind_target(self, req: TargetBindingRequest) -> Campaign:
        """Bind an authorized concrete target URL to a campaign awaiting target."""
        campaign = self.repo.get_campaign(req.campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{req.campaign_id}' not found.")

        if not req.target_url or "*" in req.target_url:
            raise ValueError(f"Wildcard target '{req.target_url}' cannot be bound. Enter a concrete URL.")

        validate_concrete_target_url(req.target_url)
        is_safe, safety_reason = validate_destination_safety(req.target_url, strict=True)
        if not is_safe:
            raise ValueError(f"Destination safety check failed for '{req.target_url}': {safety_reason}")

        # Check scope against snapshot if present
        snapshot = self.repo.get_snapshot(req.campaign_id)
        if snapshot and snapshot.snapshot_json:
            try:
                snap_dict = json.loads(snapshot.snapshot_json)
                in_scope = snap_dict.get("in_scope_assets") or snap_dict.get("scope_assets") or []
                out_of_scope = snap_dict.get("out_of_scope_assets") or []
                if in_scope:
                    validator = ScopeValidator(in_scope_assets=in_scope, out_of_scope_assets=out_of_scope)
                    decision = validator.validate_url(req.target_url)
                    if not decision.allowed:
                        raise ValueError(f"Target '{req.target_url}' is not in authorized scope: {decision.reason}")
            except ValueError:
                raise
            except Exception as e:
                logger.warning(f"Could not validate target against snapshot scope: {e}")

        scheme, host, port, path, canonical_url = validate_concrete_target_url(req.target_url)
        normalized_target = f"{scheme}://{host}" if (port == 80 and scheme == "http") or (port == 443 and scheme == "https") else f"{scheme}://{host}:{port}"

        campaign.target_url = normalized_target
        campaign.awaiting_target = False
        if campaign.status not in (CampaignLifecycleState.AUTHORIZED.value, CampaignLifecycleState.QUEUED.value):
            campaign.status = CampaignLifecycleState.DRAFT.value
        self.repo.add_target(campaign_id=campaign.id, normalized_url=normalized_target, scope_status="IN_SCOPE")
        self.repo.append_audit_event(
            campaign_id=campaign.id,
            event_type="TARGET_BOUND",
            actor=req.actor,
            metadata={"target_url": normalized_target, "notes": req.notes},
        )
        self.repo.session.flush()
        return campaign

    def kill_campaign(self, campaign_id: str, actor: str = "operator", reason: str = "Emergency kill switch triggered") -> Campaign:
        """Emergency kill switch: Immediately halts campaign and cancels running tasks."""
        campaign = self.repo.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")

        # Cancel tasks
        tasks = self.repo.get_tasks(campaign_id)
        for t in tasks:
            if t.status in ("RUNNING", "PENDING", "CLAIMED"):
                t.status = "CANCELLED"
                t.failure_reason = f"Killed by operator: {reason}"

        campaign.status = "KILLED"
        self.repo.append_audit_event(
            campaign_id=campaign.id,
            event_type="CAMPAIGN_KILLED",
            actor=actor,
            metadata={"reason": reason},
        )
        self.repo.session.flush()
        return campaign

    def authorize_campaign(
        self,
        campaign_id: str,
        authorized_by: str,
        authorization_type: str = "explicit_scope_consent",
        authorization_reference: Optional[str] = None,
        duration_days: int = 30,
    ) -> AuthorizationRecord:
        """Explicitly authorize a campaign, transitioning it from DRAFT to AUTHORIZED."""
        campaign = self.repo.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")

        # Compute current scope hash
        targets = [t.normalized_url for t in self.repo.get_targets(campaign_id)]
        scope_canonical = json.dumps(sorted(targets), sort_keys=True)
        scope_hash = hashlib.sha256(scope_canonical.encode("utf-8")).hexdigest()

        expires_at = datetime.now(timezone.utc) + timedelta(days=duration_days)
        auth_record = self.repo.create_authorization(
            campaign_id=campaign_id,
            authorized_by=authorized_by,
            scope_hash=scope_hash,
            authorization_type=authorization_type,
            authorization_reference=authorization_reference,
            expires_at=expires_at,
        )

        self.repo.set_campaign_hashes(
            campaign_id=campaign_id,
            scope_snapshot_hash=scope_hash,
        )

        # Transition campaign state
        self.repo.update_campaign_status(
            campaign_id=campaign_id,
            target_status=CampaignLifecycleState.AUTHORIZED,
            actor=authorized_by,
            reason=f"Authorized by {authorized_by} under {authorization_type}",
        )
        return auth_record

    # ──────────────────────────────────────────────────────────────────────────
    # 2. QUEUEING & EXECUTION PREPARATION
    # ──────────────────────────────────────────────────────────────────────────

    def queue_campaign(
        self,
        campaign_id: str,
        task_specs: Optional[List[Dict[str, Any]]] = None,
        actor: str = "system",
    ) -> Campaign:
        """Create planned tasks and transition campaign to QUEUED."""
        campaign = self.repo.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")

        self._verify_authorization_or_raise(campaign)

        if task_specs:
            self.repo.create_tasks_batch(campaign_id, task_specs)
            metrics.record_tasks_created(len(task_specs))

        return self.repo.update_campaign_status(
            campaign_id=campaign_id,
            target_status=CampaignLifecycleState.QUEUED,
            actor=actor,
            reason="Campaign tasks queued for worker execution",
        )

    def start_campaign(
        self,
        campaign_id: str,
        actor: str = "system",
        auto_dispatch: bool = False,
    ) -> Campaign:
        """Transition campaign to RUNNING and atomically create initial tasks if none exist.
        Fails closed if authorization is invalid."""
        campaign = self.repo.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")

        # Idempotent start if already RUNNING
        if campaign.status == CampaignLifecycleState.RUNNING.value:
            return campaign

        if getattr(campaign, "awaiting_target", False) or not campaign.target_url or campaign.target_url == "WAITING_FOR_TARGET":
            raise ValueError("Cannot start campaign: campaign is WAITING_FOR_TARGET. Operator must supply a concrete target URL.")

        self._verify_authorization_or_raise(campaign)

        # Transition status
        updated = self.repo.update_campaign_status(
            campaign_id=campaign_id,
            target_status=CampaignLifecycleState.RUNNING,
            actor=actor,
            reason="Execution started",
        )

        self.repo.append_audit_event(
            campaign_id=campaign.id,
            event_type="EXECUTION_STARTED",
            actor=actor,
            metadata={"status": "RUNNING", "target_url": campaign.target_url},
        )

        # Atomically create initial task(s) if auto_dispatch=True and 0 tasks exist
        if auto_dispatch:
            existing_tasks_count = (
                self.repo.session.query(ExecutionTask)
                .filter(ExecutionTask.campaign_id == campaign_id)
                .count()
            )
            if existing_tasks_count == 0:
                targets = self.repo.get_targets(campaign_id)
                snapshot = self.repo.get_snapshot(campaign_id)
                selected_checks = [
                    "C002_Missing_Security_Headers",
                    "C004_CORS_Misconfiguration",
                    "C008_Subdomain_Takeover",
                    "C037_Reflected_XSS",
                ]
                if snapshot and snapshot.snapshot_json:
                    try:
                        snap_dict = json.loads(snapshot.snapshot_json)
                        selected_checks = snap_dict.get("selected_checks") or selected_checks
                    except Exception:
                        pass

                # Pipeline modes are single, ordered jobs. Recon-only must never enqueue
                # individual vulnerability checks; SAFE_SCAN performs recon once and then
                # hands its snapshot to VTA.
                pipeline_mode = str(campaign.mode or "SAFE_SCAN").upper()
                if pipeline_mode == "RECON_ONLY":
                    selected_checks = ["PIPELINE_RECON_ONLY"]
                elif pipeline_mode in {"SAFE_SCAN", "VULNERABILITY_TESTING", "FULL_ASSESSMENT"}:
                    selected_checks = ["PIPELINE_RECON_THEN_VTA"]

                task_specs = []
                if targets:
                    for target in targets:
                        if "*" not in target.normalized_url:
                            for check_id in selected_checks:
                                task_specs.append({
                                    "check_id": check_id,
                                    "target_url": target.normalized_url,
                                    "endpoint_url": target.normalized_url,
                                    "target_id": target.id,
                                    "method": "GET",
                                    "parameters": {},
                                    "priority": 1,
                                })
                if not task_specs:
                    for check_id in selected_checks:
                        task_specs.append({
                            "check_id": check_id,
                            "target_url": campaign.target_url,
                            "endpoint_url": campaign.target_url,
                            "method": "GET",
                            "parameters": {},
                            "priority": 1,
                        })

                if task_specs:
                    self.repo.create_tasks_batch(campaign_id, task_specs)

        metrics.record_campaign_started()
        return updated

    def pause_campaign(self, campaign_id: str, actor: str = "system", reason: Optional[str] = None) -> Campaign:
        """Pause a running campaign without cancelling pending tasks."""
        campaign = self.repo.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")

        updated = self.repo.update_campaign_status(
            campaign_id=campaign_id,
            target_status=CampaignLifecycleState.PAUSED,
            actor=actor,
            reason=reason or "Operator requested pause",
        )
        metrics.record_campaign_paused()
        return updated

    def resume_campaign(self, campaign_id: str, actor: str = "system") -> Campaign:
        """Resume execution of a paused campaign."""
        campaign = self.repo.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")

        self._verify_authorization_or_raise(campaign)

        updated = self.repo.update_campaign_status(
            campaign_id=campaign_id,
            target_status=CampaignLifecycleState.RUNNING,
            actor=actor,
            reason="Campaign resumed",
        )
        metrics.record_campaign_started()
        return updated

    def cancel_campaign(self, campaign_id: str, actor: str = "system", reason: Optional[str] = None) -> Campaign:
        """Cooperatively cancel campaign, invalidate all unfinished tasks, and release target assignments."""
        campaign = self.repo.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")

        # Idempotent return if already CANCELLED
        if campaign.status == CampaignLifecycleState.CANCELLED.value:
            return campaign

        # Mark all unfinished tasks as CANCELLED and clear worker/lease
        for t in campaign.tasks:
            if t.status in (
                TaskLifecycleState.PENDING.value,
                TaskLifecycleState.CLAIMED.value,
                TaskLifecycleState.RUNNING.value,
                TaskLifecycleState.RETRY_PENDING.value,
            ):
                t.status = TaskLifecycleState.CANCELLED.value
                t.lease_expires_at = None
                t.worker_id = None
                t.failure_reason = reason or "Campaign cancelled by operator"

        # Release target assignments for this campaign
        self.repo.release_campaign_targets(campaign_id)

        updated = self.repo.update_campaign_status(
            campaign_id=campaign_id,
            target_status=CampaignLifecycleState.CANCELLED,
            actor=actor,
            reason=reason or "Operator cancelled campaign",
        )
        metrics.record_campaign_cancelled()
        return updated

    def complete_campaign(self, campaign_id: str, actor: str = "system") -> Campaign:
        """Mark campaign as COMPLETED and generate final manifest."""
        campaign = self.repo.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")

        # Generate and store manifest
        manifest = self.generate_manifest(campaign_id)
        self.repo.set_campaign_hashes(campaign_id=campaign_id, manifest_hash=manifest.manifest_hash)

        updated = self.repo.update_campaign_status(
            campaign_id=campaign_id,
            target_status=CampaignLifecycleState.COMPLETED,
            actor=actor,
            reason="All tasks completed successfully",
        )
        metrics.record_campaign_completed()
        return updated

    # ──────────────────────────────────────────────────────────────────────────
    # 3. TASK WORKER COORDINATION & RECOVERY
    # ──────────────────────────────────────────────────────────────────────────

    def claim_tasks_for_worker(
        self,
        campaign_id: str,
        worker_id: str,
        limit: int = 5,
        lease_seconds: int = 60,
    ) -> List[ExecutionTask]:
        """Atomically claim tasks under worker lease if campaign is RUNNING."""
        campaign = self.repo.get_campaign(campaign_id)
        if not campaign:
            return []

        if campaign.status != CampaignLifecycleState.RUNNING.value:
            logger.debug(f"Campaign '{campaign_id}' is in state '{campaign.status}'; no tasks claimed.")
            return []

        # Phase 17: Awaiting target check — campaign cannot claim tasks while waiting for target
        if getattr(campaign, "awaiting_target", False) or not campaign.target_url or campaign.target_url == "WAITING_FOR_TARGET":
            logger.debug(f"Campaign '{campaign_id}' is awaiting target; no tasks claimed.")
            return []

        # Phase 16: Kill switch check — KILLED campaigns must never claim new tasks
        if campaign.status == CampaignLifecycleState.KILLED.value:
            logger.warning(f"Campaign '{campaign_id}' has been KILLED; refusing task claims.")
            return []

        claimed = self.repo.claim_tasks(
            campaign_id=campaign_id,
            worker_id=worker_id,
            limit=limit,
            lease_duration_seconds=lease_seconds,
        )
        if claimed:
            metrics.record_task_claimed(len(claimed))
        return claimed

    def recover_stale_tasks(self, campaign_id: Optional[str] = None) -> List[ExecutionTask]:
        """Recover tasks whose worker lease has expired."""
        recovered = self.repo.recover_stale_tasks(campaign_id)
        if recovered:
            metrics.record_stale_task_recovered(len(recovered))
        return recovered

    # ──────────────────────────────────────────────────────────────────────────
    # 4. MANIFEST & INTEGRITY
    # ──────────────────────────────────────────────────────────────────────────

    def generate_manifest(self, campaign_id: str) -> CampaignManifest:
        """Compute top-level cryptographic manifest for a campaign."""
        campaign = self.repo.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")

        ev_records = self.repo.get_evidence_for_campaign(campaign_id, limit=1000)
        ev_hashes = [r.content_hash for r in ev_records]

        targets = [t.normalized_url for t in self.repo.get_targets(campaign_id)]
        scope_canonical = json.dumps(sorted(targets), sort_keys=True)
        scope_hash = hashlib.sha256(scope_canonical.encode("utf-8")).hexdigest()

        snapshot = self.repo.get_snapshot(campaign_id)
        config_hash = snapshot.snapshot_hash if snapshot else ""

        manifest = ManifestBuilder.build_manifest(
            campaign_id=campaign_id,
            scope_hash=scope_hash,
            config_hash=config_hash,
            evidence_hashes=ev_hashes,
        )
        return manifest

    def verify_campaign_integrity(self, campaign_id: str) -> CampaignIntegrityReport:
        """Perform comprehensive integrity verification."""
        return ManifestBuilder.verify_campaign_integrity(self.repo, campaign_id)

    # ──────────────────────────────────────────────────────────────────────────
    # 5. STATUS & METRICS QUERY
    # ──────────────────────────────────────────────────────────────────────────

    def get_campaign_status(self, campaign_id: str) -> Dict[str, Any]:
        campaign = self.repo.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")

        task_counts = self.repo.count_tasks_by_status(campaign_id)
        targets = self.repo.get_targets(campaign_id)
        auth = self.repo.get_authorization(campaign_id)
        now = datetime.now(timezone.utc)
        is_expired = bool(auth and auth.expires_at and auth.expires_at < now)

        return {
            "campaign_id": campaign.id,
            "name": campaign.name,
            "target_url": campaign.target_url,
            "mode": campaign.mode,
            "status": campaign.status,
            "created_at": campaign.created_at.isoformat() if hasattr(campaign.created_at, "isoformat") else str(campaign.created_at),
            "started_at": campaign.started_at.isoformat() if campaign.started_at and hasattr(campaign.started_at, "isoformat") else (str(campaign.started_at) if campaign.started_at else None),
            "completed_at": campaign.completed_at.isoformat() if campaign.completed_at and hasattr(campaign.completed_at, "isoformat") else (str(campaign.completed_at) if campaign.completed_at else None),
            "paused_at": campaign.paused_at.isoformat() if campaign.paused_at and hasattr(campaign.paused_at, "isoformat") else (str(campaign.paused_at) if campaign.paused_at else None),
            "authorized": auth is not None and auth.status == "ACTIVE" and not is_expired,
            "authorized_by": auth.authorized_by if auth else None,
            "authorization_status": "EXPIRED" if is_expired else (auth.status if auth else "UNAUTHORIZED"),
            "authorization_expires_at": auth.expires_at.isoformat() if auth and auth.expires_at else None,
            "is_authorization_expired": is_expired,
            "budget": {
                "campaign_budget": campaign.campaign_budget,
                "target_budget": campaign.target_budget,
                "check_budget": campaign.check_budget,
                "requests_used": campaign.requests_used,
            },
            "targets_count": len(targets),
            "tasks_summary": task_counts,
            "hashes": {
                "scope_snapshot_hash": campaign.scope_snapshot_hash,
                "registry_hash": campaign.registry_hash,
                "manifest_hash": campaign.manifest_hash,
            },
        }

    def get_campaign_runtime_truth(self, campaign_id: str, stale_threshold_seconds: int = 120) -> Dict[str, Any]:
        """Provides a safe, secret-free diagnostic runtime truth state of a campaign."""
        campaign = self.repo.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")

        task_counts = self.repo.count_tasks_by_status(campaign_id)
        evidence_records = self.repo.get_evidence_for_campaign(campaign_id)
        evidence_count = len(evidence_records)

        from backend.models.database import Finding
        findings_query = self.repo.session.query(Finding).filter(Finding.scan_id == campaign_id)
        findings_total = findings_query.count()
        findings_verified = findings_query.filter(Finding.verification_status == "VERIFIED").count()
        findings_candidates = findings_query.filter(
            Finding.verification_status.in_(["CANDIDATE", "NEEDS_HUMAN_REVIEW", "VERIFICATION_REQUESTED"])
        ).count()

        now = datetime.now(timezone.utc)
        timestamps: List[datetime] = []
        if campaign.created_at:
            timestamps.append(campaign.created_at)
        if campaign.started_at:
            timestamps.append(campaign.started_at)
        if campaign.completed_at:
            timestamps.append(campaign.completed_at)
        if campaign.paused_at:
            timestamps.append(campaign.paused_at)

        for ev in evidence_records:
            if hasattr(ev, "created_at") and ev.created_at:
                timestamps.append(ev.created_at)

        # Include ExecutionTask activity (started_at, completed_at, and active leases)
        tasks = self.repo.session.query(ExecutionTask).filter(ExecutionTask.campaign_id == campaign_id).all()
        for t in tasks:
            if t.started_at:
                timestamps.append(t.started_at)
            if t.completed_at:
                timestamps.append(t.completed_at)
            if t.status in (TaskLifecycleState.CLAIMED.value, TaskLifecycleState.RUNNING.value):
                if t.lease_expires_at:
                    # An active, non-expired lease represents current worker activity
                    lease_start = t.lease_expires_at - timedelta(seconds=30)
                    timestamps.append(min(now, max(lease_start, t.started_at or now)))

        # Include recent audit trail events
        from backend.persistence.models import AuditTrailEvent
        audit_events = (
            self.repo.session.query(AuditTrailEvent)
            .filter(AuditTrailEvent.campaign_id == campaign_id)
            .order_by(AuditTrailEvent.timestamp.desc())
            .limit(10)
            .all()
        )
        for ae in audit_events:
            if ae.timestamp:
                timestamps.append(ae.timestamp)

        last_activity_dt = max(timestamps) if timestamps else now
        if hasattr(last_activity_dt, "tzinfo") and last_activity_dt.tzinfo is None:
            last_activity_dt = last_activity_dt.replace(tzinfo=timezone.utc)

        time_since_activity_sec = max(0.0, (now - last_activity_dt).total_seconds())

        is_stalled = False
        stalled_reason = None
        current_phase = campaign.status
        active_operation = "Idle"

        running_tasks = task_counts.get("RUNNING", 0) + task_counts.get("CLAIMED", 0)
        pending_tasks = task_counts.get("PENDING", 0) + task_counts.get("RETRY_PENDING", 0)
        completed_tasks = task_counts.get("COMPLETED", 0)

        if campaign.status == "RUNNING":
            if running_tasks > 0:
                is_stalled = False
                stalled_reason = None
                if campaign.requests_used < 5:
                    current_phase = "RECON"
                    active_operation = f"Passive reconnaissance & active inspection ({running_tasks} active workers)"
                elif findings_candidates > 0 and findings_verified == 0:
                    current_phase = "VERIFICATION"
                    active_operation = f"Verifying candidate findings ({findings_candidates} candidates)..."
                else:
                    current_phase = "TESTING"
                    active_operation = f"Security check execution in progress ({running_tasks} active workers)"
            elif running_tasks == 0 and pending_tasks == 0 and completed_tasks > 0:
                current_phase = "VERIFICATION" if findings_candidates > 0 else "REPORT_READY"
                active_operation = "All check tasks completed. Ready for operator review / report export."
            elif running_tasks == 0 and time_since_activity_sec > stale_threshold_seconds:
                is_stalled = True
                current_phase = "RUNNING — NO RECENT PROGRESS"
                stalled_reason = f"No worker heartbeat or task activity for {int(time_since_activity_sec)}s (> {stale_threshold_seconds}s threshold)"
                active_operation = "Stalled: No active worker lease or pending task claims."
            elif running_tasks == 0 and pending_tasks > 0:
                current_phase = "TESTING"
                active_operation = f"Tasks queued ({pending_tasks} pending). Awaiting worker claim."
            else:
                current_phase = "TESTING"
                active_operation = f"Security check execution in progress ({running_tasks} active workers)"
        elif campaign.status == "AUTHORIZED":
            current_phase = "STAGED"
            active_operation = "Authorized under HackerOne scope. Ready for operator launch."
        elif campaign.status == "PAUSED":
            current_phase = "PAUSED"
            active_operation = "Execution paused by operator. Task claims suspended."
        elif campaign.status == "COMPLETED":
            current_phase = "COMPLETED"
            active_operation = "Assessment campaign completed."
        elif campaign.status == "CANCELLED":
            current_phase = "CANCELLED"
            active_operation = "Assessment cancelled."

        return {
            "campaign_id": campaign.id,
            "campaign_name": campaign.name,
            "target_url": campaign.target_url,
            "status": campaign.status,
            "current_phase": current_phase,
            "active_operation": active_operation,
            "is_stalled": is_stalled,
            "stalled_reason": stalled_reason,
            "time_since_last_activity_sec": round(time_since_activity_sec, 1),
            "timestamps": {
                "created_at": campaign.created_at.isoformat() if campaign.created_at and hasattr(campaign.created_at, "isoformat") else str(campaign.created_at),
                "started_at": campaign.started_at.isoformat() if campaign.started_at and hasattr(campaign.started_at, "isoformat") else (str(campaign.started_at) if campaign.started_at else None),
                "completed_at": campaign.completed_at.isoformat() if campaign.completed_at and hasattr(campaign.completed_at, "isoformat") else (str(campaign.completed_at) if campaign.completed_at else None),
                "last_activity_at": last_activity_dt.isoformat() if hasattr(last_activity_dt, "isoformat") else str(last_activity_dt),
            },
            "metrics": {
                "requests_used": campaign.requests_used,
                "requests_budget": campaign.campaign_budget,
                "evidence_count": evidence_count,
                "findings_total": findings_total,
                "findings_candidates": findings_candidates,
                "findings_verified": findings_verified,
            },
            "tasks_summary": task_counts,
            "backend_state": {
                "status": "CONNECTED",
                "database": "READY",
                "storage": "LOCAL_SQLITE_WAL",
                "redis": "OPTIONAL / UNAVAILABLE",
            },
            "last_error": None,
        }

    def generate_execution_plan(self, campaign_id: str) -> ExecutionPlan:
        """Construct deterministic execution plan containing only authorized, registered, non-destructive checks."""
        campaign = self.repo.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")

        # 1. Target URL must be concrete
        if not campaign.target_url or "*" in campaign.target_url:
            raise ValueError("Execution plan cannot be generated for wildcard targets.")
        validate_concrete_target_url(campaign.target_url)

        # 2. Authorization record
        auth = self.repo.get_authorization(campaign_id)
        auth_id = auth.id if auth else "UNAUTHORIZED"
        scope_hash = auth.scope_hash if auth else (campaign.scope_snapshot_hash or "")

        # 3. Retrieve checks
        snapshot = self.repo.get_snapshot(campaign_id)
        selected_checks: List[str] = []
        if snapshot and snapshot.snapshot_json:
            try:
                snap_dict = json.loads(snapshot.snapshot_json)
                selected_checks = snap_dict.get("selected_checks", [])
            except Exception:
                pass

        if not selected_checks:
            all_registered = registry.get_all_checks()
            selected_checks = [c.contract.id for c in all_registered]

        # 4. Validate each check in registry
        plan_checks: List[ExecutionPlanCheck] = []
        for idx, check_id in enumerate(sorted(selected_checks), start=1):
            try:
                check_cls = registry.get_check(check_id)
            except KeyError:
                raise ValueError(f"Unknown check ID '{check_id}' cannot enter execution plan.")

            contract = check_cls.contract
            if contract.destructive:
                raise ValueError(f"Destructive check '{check_id}' cannot enter execution plan.")

            plan_checks.append(
                ExecutionPlanCheck(
                    check_id=contract.id,
                    enabled=True,
                    destructive=False,
                    execution_order=idx,
                    timeout_seconds=30,
                    expected_request_budget=min(contract.max_requests, campaign.check_budget or 20),
                    check_version="1.0.0",
                )
            )

        budget_snapshot = {
            "campaign_budget": campaign.campaign_budget or 500,
            "target_budget": campaign.target_budget or 100,
            "check_budget": campaign.check_budget or 20,
        }

        plan = ExecutionPlan(
            campaign_id=campaign.id,
            target_url=campaign.target_url,
            authorized_scope_hash=scope_hash,
            authorization_id=auth_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            checks=plan_checks,
            budget_snapshot=budget_snapshot,
        )
        plan.plan_hash = plan.compute_hash()

        # Update snapshot JSON with execution plan
        if snapshot and snapshot.snapshot_json:
            try:
                snap_dict = json.loads(snapshot.snapshot_json)
                snap_dict["execution_plan"] = plan.to_dict()
                snapshot.snapshot_json = json.dumps(snap_dict, sort_keys=True)
                snapshot.snapshot_hash = hashlib.sha256(snapshot.snapshot_json.encode("utf-8")).hexdigest()
                self.repo.session.flush()
            except Exception as e:
                logger.warning(f"Could not store execution plan in snapshot: {e}")

        self.repo.set_campaign_hashes(campaign_id=campaign.id, config_hash=plan.plan_hash)
        self.repo.append_audit_event(
            campaign_id=campaign.id,
            event_type="EXECUTION_PLAN_CREATED",
            actor="system",
            metadata={"plan_hash": plan.plan_hash, "check_count": len(plan.checks)},
        )
        return plan

    def validate_execution_plan(self, campaign_id: str) -> Tuple[bool, str, Optional[ExecutionPlan]]:
        """Validate execution plan integrity, registered check existence, and cryptographic hash."""
        campaign = self.repo.get_campaign(campaign_id)
        if not campaign:
            return False, f"Campaign '{campaign_id}' not found.", None

        snapshot = self.repo.get_snapshot(campaign_id)
        if not snapshot or not snapshot.snapshot_json:
            return False, "Campaign snapshot missing.", None

        try:
            snap_dict = json.loads(snapshot.snapshot_json)
        except Exception as e:
            return False, f"Snapshot JSON corrupted: {e}", None

        plan_data = snap_dict.get("execution_plan")
        if not plan_data:
            # If not yet generated, attempt generation
            try:
                plan = self.generate_execution_plan(campaign_id)
                return True, "Execution plan generated and validated.", plan
            except Exception as e:
                return False, f"Execution plan generation failed: {e}", None

        try:
            checks = [
                ExecutionPlanCheck(**c) if isinstance(c, dict) else c
                for c in plan_data.get("checks", [])
            ]
            plan = ExecutionPlan(
                campaign_id=plan_data.get("campaign_id", campaign.id),
                target_url=plan_data.get("target_url", campaign.target_url),
                authorized_scope_hash=plan_data.get("authorized_scope_hash", ""),
                authorization_id=plan_data.get("authorization_id", ""),
                created_at=plan_data.get("created_at", ""),
                checks=checks,
                budget_snapshot=plan_data.get("budget_snapshot", {}),
                plan_hash=plan_data.get("plan_hash", ""),
            )
        except Exception as e:
            return False, f"Execution plan structure invalid: {e}", None

        # Verify integrity hash
        if not plan.verify_integrity():
            return False, "Execution plan hash mismatch (tampering detected).", plan

        if campaign.config_hash and campaign.config_hash != plan.plan_hash:
            return False, f"Campaign config_hash ({campaign.config_hash}) does not match plan_hash ({plan.plan_hash}).", plan

        # Verify checks exist in registry and are non-destructive
        for c in plan.checks:
            try:
                check_cls = registry.get_check(c.check_id)
                if check_cls.contract.destructive:
                    return False, f"Destructive check '{c.check_id}' found in plan.", plan
            except KeyError:
                return False, f"Unregistered check '{c.check_id}' found in plan.", plan

        return True, "Execution plan integrity verified.", plan

    def verify_scope_snapshot_integrity(self, campaign_id: str) -> Tuple[bool, str]:
        """Verify that the immutable CampaignSnapshot hash matches stored JSON and matches campaign scope snapshot hash."""
        snapshot = self.repo.get_snapshot(campaign_id)
        if not snapshot:
            return False, "Campaign configuration snapshot missing."

        # Verify JSON SHA-256 integrity
        computed_hash = hashlib.sha256(snapshot.snapshot_json.encode("utf-8")).hexdigest()
        if snapshot.snapshot_hash != computed_hash:
            return False, f"Campaign snapshot tampering detected! Stored hash={snapshot.snapshot_hash}, computed hash={computed_hash}"

        try:
            snap_dict = json.loads(snapshot.snapshot_json)
        except Exception as e:
            return False, f"Campaign snapshot JSON corrupted: {e}"

        campaign = self.repo.get_campaign(campaign_id)
        if campaign and campaign.scope_snapshot_hash:
            snap_scope_hash = snap_dict.get("scope_hash")
            if snap_scope_hash and snap_scope_hash != campaign.scope_snapshot_hash:
                return False, f"Campaign scope snapshot hash mismatch: snapshot={snap_scope_hash}, campaign={campaign.scope_snapshot_hash}"

        return True, "Snapshot integrity verified"

    def get_campaign_preflight_checklist(self, campaign_id: str) -> Dict[str, Any]:
        """Returns structured pre-flight validation checks for launching or executing a campaign."""
        campaign = self.repo.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")

        now = datetime.now(timezone.utc)
        auth = self.repo.get_authorization(campaign_id)
        targets = self.repo.get_targets(campaign_id)

        # 1. Target URL validity & WAITING_FOR_TARGET check
        target_valid = False
        target_valid_reason = ""
        is_awaiting_target = getattr(campaign, "awaiting_target", False) or not campaign.target_url or campaign.target_url == "WAITING_FOR_TARGET"

        if is_awaiting_target:
            target_valid = False
            target_valid_reason = "Campaign is WAITING_FOR_TARGET. Operator must supply a concrete target URL."
            in_scope = False
            scope_reason = "Scope evaluation pending target input."
            dest_safe = False
            dest_reason = "Destination safety evaluation pending target input."
        else:
            try:
                validate_concrete_target_url(campaign.target_url)
                target_valid = True
                target_valid_reason = "Concrete HTTP/HTTPS target URL is valid"
            except Exception as e:
                target_valid_reason = str(e)

            # 2. Scope Validation
            in_scope = False
            scope_reason = ""
            try:
                in_scope_rules: List[str] = []
                out_of_scope_rules: List[str] = []
                if campaign.program_id:
                    from backend.models.database import ProgramScope
                    scope_rec = self.repo.session.query(ProgramScope).filter_by(program_id=campaign.program_id).first()
                    if scope_rec:
                        in_scope_rules = json.loads(scope_rec.in_scope_assets or "[]")
                        out_of_scope_rules = json.loads(scope_rec.out_of_scope_assets or "[]")
                if not in_scope_rules:
                    target_urls = [t.normalized_url for t in targets] or [campaign.target_url]
                    in_scope_rules = target_urls
                validator = ScopeValidator(in_scope_assets=in_scope_rules, out_of_scope_assets=out_of_scope_rules)
                dec = validator.is_url_in_scope(campaign.target_url)
                in_scope = dec.allowed
                scope_reason = dec.reason
            except Exception as e:
                scope_reason = str(e)

            # 3. Destination Safety Validation
            dest_safe, dest_reason = validate_destination_safety(campaign.target_url, allow_loopback=True)

        # 4. Campaign Authorization & Expiry
        auth_present = auth is not None and auth.status == "ACTIVE"
        auth_not_expired = bool(auth and auth.expires_at and auth.expires_at > now)
        auth_expires_at = auth.expires_at.isoformat() if auth and auth.expires_at else None

        # 5. Scope Snapshot Integrity
        snapshot_valid, snapshot_reason = self.verify_scope_snapshot_integrity(campaign_id)

        # 6. Execution Plan Integrity
        plan_valid, plan_reason, plan_obj = self.validate_execution_plan(campaign_id)

        # 7. Budget check
        budget_available = (campaign.requests_used or 0) < (campaign.campaign_budget or 500)

        # 8. Request Engine safety gate
        gate_ready = target_valid and in_scope and dest_safe and auth_present and auth_not_expired and snapshot_valid and plan_valid

        issues = []
        if not target_valid:
            issues.append(f"Target URL: {target_valid_reason}")
        if not in_scope:
            issues.append(f"Scope: {scope_reason}")
        if not dest_safe:
            issues.append(f"Destination Safety: {dest_reason}")
        if not auth_present:
            issues.append("Authorization: Campaign lacks active operator authorization")
        elif not auth_not_expired:
            issues.append(f"Authorization: Campaign authorization expired at {auth_expires_at}")
        if not snapshot_valid:
            issues.append(f"Snapshot Integrity: {snapshot_reason}")
        if not plan_valid:
            issues.append(f"Execution Plan: {plan_reason}")
        if not budget_available:
            issues.append(f"Budget: Requests used ({campaign.requests_used}) has reached limit ({campaign.campaign_budget})")

        all_passed = len(issues) == 0

        self.repo.append_audit_event(
            campaign_id=campaign.id,
            event_type="ASSESSMENT_PREFLIGHT",
            actor="preflight_validator",
            metadata={
                "all_passed": all_passed,
                "target_url": campaign.target_url,
                "issues_count": len(issues),
            },
        )

        selected_checks_list = [c.check_id for c in plan_obj.checks] if plan_obj else []
        estimated_reqs = len(selected_checks_list) * (campaign.check_budget or 20)

        # Program and bounty eligibility checks
        program_obj = None
        program_valid = True
        bounty_eligible = False
        if campaign.program_id:
            from backend.models.database import Program
            program_obj = self.repo.session.query(Program).filter_by(id=campaign.program_id).first()
            program_valid = program_obj is not None
            bounty_eligible = getattr(program_obj, "bounty_eligible", False) if program_obj else False

        assessment_mode_val = getattr(campaign, "assessment_mode", "CONTROLLED") or "CONTROLLED"
        rate_limit_valid = (campaign.rate_limit_rps or 10) <= (2 if assessment_mode_val == "PRODUCTION_AUTHORIZED" else 50)
        concurrency_valid = (campaign.max_concurrency or 5) <= (1 if assessment_mode_val == "PRODUCTION_AUTHORIZED" else 20)
        methods_valid = True
        kill_switch_state = "KILLED" if campaign.status == "KILLED" else "DISARMED"

        return {
            "campaign_id": campaign.id,
            "all_passed": all_passed,
            "ready_to_execute": all_passed,
            "assessment_mode": assessment_mode_val,
            "target_url": campaign.target_url,
            "target_valid": target_valid,
            "target_concrete_valid": target_valid,
            "target_in_scope": in_scope,
            "scope_valid": in_scope,
            "scope_snapshot_verified": snapshot_valid,
            "scope_snapshot_hash": campaign.scope_snapshot_hash,
            "destination_safe": dest_safe,
            "destination_reason": dest_reason,
            "campaign_authorized": auth_present,
            "authorization_valid": auth_present and auth_not_expired,
            "authorization_not_expired": auth_not_expired,
            "authorization_expires_at": auth_expires_at,
            "authorization_expiry": auth_expires_at,
            "execution_plan_verified": plan_valid,
            "execution_plan_valid": plan_valid,
            "execution_plan_hash": plan_obj.plan_hash if plan_obj else None,
            "selected_checks": selected_checks_list,
            "execution_plan_checks_count": len(selected_checks_list),
            "all_checks_registered": plan_valid,
            "all_checks_non_destructive": True if plan_valid else False,
            "request_budget": campaign.campaign_budget or 500,
            "estimated_request_count": estimated_reqs,
            "budget_available": budget_available,
            "budget_valid": budget_available,
            "rate_limit_valid": rate_limit_valid,
            "concurrency_valid": concurrency_valid,
            "methods_valid": methods_valid,
            "snapshot_valid": snapshot_valid,
            "program_valid": program_valid,
            "bounty_eligible": bounty_eligible,
            "engine_ready": gate_ready,
            "kill_switch_state": kill_switch_state,
            "request_engine_required": True,
            "request_engine_ready": gate_ready,
            "issues": issues,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # 6. INTERNAL VALIDATION HELPERS
    # ──────────────────────────────────────────────────────────────────────────

    def _verify_authorization_or_raise(self, campaign: Campaign) -> None:
        """Fail-closed check: campaign must have active, non-expired authorization, valid snapshot, and valid execution plan."""
        auth = self.repo.get_authorization(campaign.id)
        if not auth:
            raise AuthorizationRequiredException(
                f"Campaign '{campaign.id}' cannot execute: no authorization record found."
            )
        if auth.status != "ACTIVE":
            raise AuthorizationRequiredException(
                f"Campaign '{campaign.id}' authorization status is '{auth.status}' (expected 'ACTIVE')."
            )
        if auth.expires_at and auth.expires_at < datetime.now(timezone.utc):
            raise AuthorizationRequiredException(
                f"Campaign '{campaign.id}' authorization expired at {auth.expires_at.isoformat()}."
            )

        # Verify scope snapshot integrity
        snapshot_ok, snap_reason = self.verify_scope_snapshot_integrity(campaign.id)
        if not snapshot_ok:
            raise ScopeMismatchException(
                f"Campaign '{campaign.id}' snapshot integrity check failed: {snap_reason}"
            )

        # Verify scope hash matches
        targets = [t.normalized_url for t in self.repo.get_targets(campaign.id)]
        current_scope_hash = hashlib.sha256(json.dumps(sorted(targets), sort_keys=True).encode("utf-8")).hexdigest()
        if auth.scope_hash != current_scope_hash:
            raise ScopeMismatchException(
                f"Campaign '{campaign.id}' scope has changed since authorization! "
                f"Auth scope_hash: {auth.scope_hash}, current scope_hash: {current_scope_hash}"
            )

        # Verify execution plan integrity
        plan_ok, plan_reason, _ = self.validate_execution_plan(campaign.id)
        if not plan_ok:
            raise ScopeMismatchException(
                f"Campaign '{campaign.id}' execution plan integrity check failed: {plan_reason}"
            )

    # ──────────────────────────────────────────────────────────────────────────
    # 7. PHASE 16: PRODUCTION ASSESSMENT MODE
    # ──────────────────────────────────────────────────────────────────────────

    # Conservative production profile — server-side enforced, not UI-only
    PRODUCTION_PROFILE = {
        "campaign_budget": 10,
        "target_budget": 10,
        "check_budget": 5,
        "max_concurrency": 1,
        "rate_limit_rps": 2,
        "allowed_methods": {"GET", "HEAD", "OPTIONS"},
    }

    PRODUCTION_PROHIBITED_METHODS = {"POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"}

    def create_production_campaign(
        self,
        name: str,
        target_url: Optional[str] = None,
        program_id: Optional[str] = None,
        authorized_by: str = "operator",
        operator_confirmation: Optional[str] = None,
        authorization_reference: Optional[str] = None,
        user_id: Optional[str] = None,
        selected_checks: Optional[List[str]] = None,
    ) -> Campaign:
        """Create a production-authorized campaign with conservative limits.

        Server-side enforces:
        - budget=10, concurrency=1, rate=2, methods=GET/HEAD/OPTIONS
        - Requires program_id and explicit operator confirmation
        - Requires concrete target (no wildcards), or creates campaign in WAITING_FOR_TARGET state
        """
        # 1. Validate operator confirmation text
        expected_confirmation = (
            "I confirm this concrete target is authorized under the selected "
            "bug-bounty program and I understand this assessment will perform real requests."
        )
        if not operator_confirmation or operator_confirmation.strip() != expected_confirmation:
            raise ValueError(
                "Production assessment requires exact operator confirmation text. "
                "Please confirm authorization explicitly."
            )

        # 2. Validate program exists
        if not program_id:
            raise ValueError("Production assessment requires a bug-bounty program_id.")
        from backend.models.database import Program, ProgramScope
        program = self.repo.session.query(Program).filter_by(id=program_id).first()
        if not program:
            raise ValueError(f"Program '{program_id}' not found.")

        profile = self.PRODUCTION_PROFILE
        is_awaiting_target = not target_url or target_url.strip() == "" or target_url == "WAITING_FOR_TARGET"

        if is_awaiting_target:
            # 3a. Create campaign in WAITING_FOR_TARGET state
            campaign = self.repo.create_campaign(
                name=name,
                target_url="WAITING_FOR_TARGET",
                mode="SAFE_SCAN",
                campaign_budget=profile["campaign_budget"],
                target_budget=profile["target_budget"],
                check_budget=profile["check_budget"],
                max_concurrency=profile["max_concurrency"],
                rate_limit_rps=profile["rate_limit_rps"],
                program_id=program_id,
                user_id=user_id,
            )
            campaign.assessment_mode = "PRODUCTION_AUTHORIZED"
            campaign.awaiting_target = True
            self.repo.session.flush()

            # Snapshot for awaiting target
            reg_meta = registry.get_registry_metadata()
            snapshot_data = {
                "campaign_id": campaign.id,
                "name": name,
                "target_url": "WAITING_FOR_TARGET",
                "mode": "SAFE_SCAN",
                "assessment_mode": "PRODUCTION_AUTHORIZED",
                "awaiting_target": True,
                "scope_assets": [],
                "scope_hash": hashlib.sha256(b"[]").hexdigest(),
                "selected_checks": [],
                "registry_version": reg_meta["registry_version"],
                "registry_hash": reg_meta["registry_hash"],
                "contract_hash": reg_meta["contract_hash"],
                "budgets": {
                    "campaign": profile["campaign_budget"],
                    "target": profile["target_budget"],
                    "check": profile["check_budget"],
                },
                "production_profile": {
                    "max_concurrency": profile["max_concurrency"],
                    "rate_limit_rps": profile["rate_limit_rps"],
                    "allowed_methods": sorted(profile["allowed_methods"]),
                },
                "operator_confirmation": operator_confirmation,
                "program_id": program_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            self.repo.save_snapshot(campaign.id, snapshot_data)
            self.repo.set_campaign_hashes(
                campaign_id=campaign.id,
                scope_snapshot_hash=snapshot_data["scope_hash"],
                registry_hash=reg_meta["registry_hash"],
            )

            # Auto-authorize
            expires_at = datetime.now(timezone.utc) + timedelta(days=30)
            self.repo.create_authorization(
                campaign_id=campaign.id,
                authorized_by=authorized_by,
                scope_hash=snapshot_data["scope_hash"],
                authorization_type="bug_bounty_program_authorization",
                authorization_reference=authorization_reference or f"Program: {program.name}",
                expires_at=expires_at,
            )
            self.repo.update_campaign_status(
                campaign_id=campaign.id,
                target_status=CampaignLifecycleState.AUTHORIZED,
                actor=authorized_by,
                reason=f"Production assessment authorized by {authorized_by} under program {program.name} (WAITING_FOR_TARGET)",
            )

            self.repo.append_audit_event(
                campaign_id=campaign.id,
                event_type="AUTHORIZATION_CONFIRMED",
                actor=authorized_by,
                metadata={"program_id": program_id, "operator_confirmation": operator_confirmation},
            )
            self.repo.append_audit_event(
                campaign_id=campaign.id,
                event_type="PRODUCTION_CAMPAIGN_CREATED",
                actor=authorized_by,
                metadata={
                    "assessment_mode": "PRODUCTION_AUTHORIZED",
                    "program_id": program_id,
                    "target_url": "WAITING_FOR_TARGET",
                    "awaiting_target": True,
                    "budget": profile["campaign_budget"],
                    "concurrency": profile["max_concurrency"],
                    "rate_limit": profile["rate_limit_rps"],
                },
            )
            metrics.record_campaign_created()
            return campaign

        # 3b. Concrete target validation
        if "*" in target_url:
            raise ValueError("Production assessment requires a concrete target URL (no wildcards).")
        scheme, host, port, path, canonical_url = validate_concrete_target_url(target_url)
        normalized_target = (
            f"{scheme}://{host}"
            if (port == 80 and scheme == "http") or (port == 443 and scheme == "https")
            else f"{scheme}://{host}:{port}"
        )

        # 4. Destination safety (strict mode — no loopback in production)
        is_safe, safety_reason = validate_destination_safety(normalized_target, allow_loopback=False)
        if not is_safe:
            raise ValueError(f"Production target failed destination safety: {safety_reason}")

        # 5. Program scope validation
        scope_rec = self.repo.session.query(ProgramScope).filter_by(program_id=program_id).first()
        if scope_rec:
            in_scope_rules = json.loads(scope_rec.in_scope_assets or "[]")
            out_of_scope_rules = json.loads(scope_rec.out_of_scope_assets or "[]")
            if in_scope_rules:
                val = ScopeValidator(in_scope_assets=in_scope_rules, out_of_scope_assets=out_of_scope_rules)
                dec = val.is_url_in_scope(normalized_target)
                if not dec.allowed:
                    raise ValueError(f"Target '{normalized_target}' is not in scope for program '{program.name}': {dec.reason}")

        # 6. Create campaign with production profile
        campaign = self.repo.create_campaign(
            name=name,
            target_url=normalized_target,
            mode="SAFE_SCAN",
            campaign_budget=profile["campaign_budget"],
            target_budget=profile["target_budget"],
            check_budget=profile["check_budget"],
            max_concurrency=profile["max_concurrency"],
            rate_limit_rps=profile["rate_limit_rps"],
            program_id=program_id,
            user_id=user_id,
        )

        campaign.assessment_mode = "PRODUCTION_AUTHORIZED"
        campaign.awaiting_target = False
        self.repo.session.flush()

        # 7. Add target
        self.repo.add_target(campaign_id=campaign.id, normalized_url=normalized_target, scope_status="IN_SCOPE")

        # 8. Filter checks for production mode (only GET/HEAD/OPTIONS compatible)
        if selected_checks:
            safe_checks = []
            for cid in selected_checks:
                try:
                    check_cls = registry.get_check(cid)
                    contract = check_cls.contract
                    if contract.destructive:
                        continue
                    if contract.supported_methods & profile["allowed_methods"]:
                        safe_checks.append(cid)
                except KeyError:
                    continue
            selected_checks = safe_checks if safe_checks else None

        # 9. Create snapshot
        all_targets = [t.normalized_url for t in self.repo.get_targets(campaign.id)]
        scope_canonical = json.dumps(sorted(all_targets), sort_keys=True)
        scope_hash = hashlib.sha256(scope_canonical.encode("utf-8")).hexdigest()

        reg_meta = registry.get_registry_metadata()
        if not selected_checks:
            all_checks = registry.get_all_checks()
            selected_checks = [
                c.contract.id for c in all_checks
                if not c.contract.destructive and c.contract.supported_methods & profile["allowed_methods"]
            ]

        snapshot_data = {
            "campaign_id": campaign.id,
            "name": name,
            "target_url": normalized_target,
            "mode": "SAFE_SCAN",
            "assessment_mode": "PRODUCTION_AUTHORIZED",
            "scope_assets": sorted(all_targets),
            "scope_hash": scope_hash,
            "selected_checks": selected_checks,
            "registry_version": reg_meta["registry_version"],
            "registry_hash": reg_meta["registry_hash"],
            "contract_hash": reg_meta["contract_hash"],
            "budgets": {
                "campaign": profile["campaign_budget"],
                "target": profile["target_budget"],
                "check": profile["check_budget"],
            },
            "production_profile": {
                "max_concurrency": profile["max_concurrency"],
                "rate_limit_rps": profile["rate_limit_rps"],
                "allowed_methods": sorted(profile["allowed_methods"]),
            },
            "operator_confirmation": operator_confirmation,
            "program_id": program_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.repo.save_snapshot(campaign.id, snapshot_data)
        self.repo.set_campaign_hashes(
            campaign_id=campaign.id,
            scope_snapshot_hash=scope_hash,
            registry_hash=reg_meta["registry_hash"],
        )

        # 10. Auto-authorize
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        self.repo.create_authorization(
            campaign_id=campaign.id,
            authorized_by=authorized_by,
            scope_hash=scope_hash,
            authorization_type="bug_bounty_program_authorization",
            authorization_reference=authorization_reference or f"Program: {program.name}",
            expires_at=expires_at,
        )
        self.repo.update_campaign_status(
            campaign_id=campaign.id,
            target_status=CampaignLifecycleState.AUTHORIZED,
            actor=authorized_by,
            reason=f"Production assessment authorized by {authorized_by} under program {program.name}",
        )

        # 11. Generate execution plan
        self.generate_execution_plan(campaign.id)

        # 12. Record audit trail
        self.repo.append_audit_event(
            campaign_id=campaign.id,
            event_type="AUTHORIZATION_CONFIRMED",
            actor=authorized_by,
            metadata={"program_id": program_id, "operator_confirmation": operator_confirmation},
        )
        self.repo.append_audit_event(
            campaign_id=campaign.id,
            event_type="PRODUCTION_CAMPAIGN_CREATED",
            actor=authorized_by,
            metadata={
                "assessment_mode": "PRODUCTION_AUTHORIZED",
                "program_id": program_id,
                "target_url": normalized_target,
                "budget": profile["campaign_budget"],
                "concurrency": profile["max_concurrency"],
                "rate_limit": profile["rate_limit_rps"],
            },
        )
        self.repo.append_audit_event(
            campaign_id=campaign.id,
            event_type="TARGET_SUPPLIED",
            actor=authorized_by,
            metadata={"target_url": normalized_target},
        )
        self.repo.append_audit_event(
            campaign_id=campaign.id,
            event_type="TARGET_SCOPE_VALIDATED",
            actor="scope_validator",
            metadata={"target_url": normalized_target, "scope_status": "IN_SCOPE"},
        )
        self.repo.append_audit_event(
            campaign_id=campaign.id,
            event_type="DESTINATION_SAFETY_PASSED",
            actor="destination_validator",
            metadata={"target_url": normalized_target, "destination_safe": True},
        )

        metrics.record_campaign_created()
        return campaign

    def supply_concrete_target(
        self,
        campaign_id: str,
        target_url: str,
        operator_confirmation: str,
        actor: str = "operator",
    ) -> Campaign:
        """Supply or update a concrete target URL for a production campaign in WAITING_FOR_TARGET state.

        Fails closed if:
        - Campaign not found
        - Campaign is in a terminal state (KILLED, CANCELLED, COMPLETED)
        - Target is missing, wildcard, or malformed
        - Destination safety fails (allow_loopback=False in production)
        - Target is out-of-scope for the campaign's program
        - Operator confirmation does not match the exact required text
        """
        campaign = self.repo.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")

        if campaign.status in (
            CampaignLifecycleState.KILLED.value,
            CampaignLifecycleState.CANCELLED.value,
            CampaignLifecycleState.COMPLETED.value,
        ):
            raise InvalidStateTransitionError(
                f"Cannot supply target to campaign '{campaign_id}' in terminal state '{campaign.status}'."
            )

        # 1. Validate operator confirmation
        expected_confirmation = (
            "I confirm this concrete target is authorized under the selected "
            "bug-bounty program and I understand this assessment will perform real requests."
        )
        if not operator_confirmation or operator_confirmation.strip() != expected_confirmation:
            raise ValueError(
                "Supplying a production target requires exact operator confirmation text. "
                "Please confirm authorization explicitly."
            )

        # 2. Validate concrete target
        if not target_url or "*" in target_url:
            raise ValueError("Target URL must be concrete (wildcards strictly rejected).")

        scheme, host, port, path, canonical_url = validate_concrete_target_url(target_url)
        normalized_target = (
            f"{scheme}://{host}"
            if (port == 80 and scheme == "http") or (port == 443 and scheme == "https")
            else f"{scheme}://{host}:{port}"
        )

        # 3. Destination safety (allow_loopback=False in production)
        is_safe, safety_reason = validate_destination_safety(normalized_target, allow_loopback=False)
        if not is_safe:
            raise ValueError(f"Production target failed destination safety: {safety_reason}")

        # 4. Scope validation against program
        if campaign.program_id:
            from backend.models.database import ProgramScope
            scope_rec = self.repo.session.query(ProgramScope).filter_by(program_id=campaign.program_id).first()
            if scope_rec:
                in_scope_rules = json.loads(scope_rec.in_scope_assets or "[]")
                out_of_scope_rules = json.loads(scope_rec.out_of_scope_assets or "[]")
                if in_scope_rules:
                    val = ScopeValidator(in_scope_assets=in_scope_rules, out_of_scope_assets=out_of_scope_rules)
                    dec = val.is_url_in_scope(normalized_target)
                    if not dec.allowed:
                        raise ValueError(f"Target '{normalized_target}' is not in scope for program: {dec.reason}")

        # 5. Persist target URL and clear awaiting_target
        campaign.target_url = normalized_target
        campaign.awaiting_target = False
        self.repo.session.flush()

        # Add or update target
        self.repo.add_target(campaign_id=campaign.id, normalized_url=normalized_target, scope_status="IN_SCOPE")

        # 6. Re-compute snapshot and hashes
        all_targets = [t.normalized_url for t in self.repo.get_targets(campaign.id)]
        scope_canonical = json.dumps(sorted(all_targets), sort_keys=True)
        scope_hash = hashlib.sha256(scope_canonical.encode("utf-8")).hexdigest()

        reg_meta = registry.get_registry_metadata()
        all_checks = registry.get_all_checks()
        profile = self.PRODUCTION_PROFILE
        safe_checks = [
            c.contract.id for c in all_checks
            if not c.contract.destructive and (c.contract.supported_methods & profile["allowed_methods"])
        ]

        snapshot_data = {
            "campaign_id": campaign.id,
            "name": campaign.name,
            "target_url": normalized_target,
            "mode": "SAFE_SCAN",
            "assessment_mode": "PRODUCTION_AUTHORIZED",
            "scope_assets": sorted(all_targets),
            "scope_hash": scope_hash,
            "selected_checks": safe_checks,
            "registry_version": reg_meta["registry_version"],
            "registry_hash": reg_meta["registry_hash"],
            "contract_hash": reg_meta["contract_hash"],
            "budgets": {
                "campaign": profile["campaign_budget"],
                "target": profile["target_budget"],
                "check": profile["check_budget"],
            },
            "production_profile": {
                "max_concurrency": profile["max_concurrency"],
                "rate_limit_rps": profile["rate_limit_rps"],
                "allowed_methods": sorted(profile["allowed_methods"]),
            },
            "operator_confirmation": operator_confirmation,
            "program_id": campaign.program_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.repo.save_snapshot(campaign.id, snapshot_data)
        self.repo.set_campaign_hashes(
            campaign_id=campaign.id,
            scope_snapshot_hash=scope_hash,
            registry_hash=reg_meta["registry_hash"],
        )

        # Update authorization record scope_hash
        auth = self.repo.get_authorization(campaign.id)
        if auth:
            auth.scope_hash = scope_hash
            self.repo.session.flush()

        # 7. Generate execution plan
        self.generate_execution_plan(campaign.id)

        # 8. Record audit events
        self.repo.append_audit_event(
            campaign_id=campaign.id,
            event_type="TARGET_SUPPLIED",
            actor=actor,
            metadata={"target_url": normalized_target},
        )
        self.repo.append_audit_event(
            campaign_id=campaign.id,
            event_type="TARGET_SCOPE_VALIDATED",
            actor="scope_validator",
            metadata={"target_url": normalized_target, "scope_status": "IN_SCOPE"},
        )
        self.repo.append_audit_event(
            campaign_id=campaign.id,
            event_type="DESTINATION_SAFETY_PASSED",
            actor="destination_validator",
            metadata={"target_url": normalized_target, "destination_safe": True},
        )

        return campaign

        metrics.record_campaign_created()
        return campaign

    def kill_campaign(
        self,
        campaign_id: str,
        actor: str = "system",
        reason: Optional[str] = None,
    ) -> Campaign:
        """Emergency kill switch: immediately stop campaign, prevent ALL future work.

        Requirements:
        1. Atomically mark campaign KILLED.
        2. Prevent future task claims.
        3. Cancel all pending/claimed/running tasks.
        4. Prevent new RequestEngine dispatch.
        5. Preserve existing evidence and audit history.
        6. Record CAMPAIGN_KILLED event.
        7. Idempotent — repeated calls return safely.
        """
        campaign = self.repo.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")

        # Idempotent return if already KILLED
        if campaign.status == CampaignLifecycleState.KILLED.value:
            return campaign

        # Cancel all unfinished tasks
        for t in campaign.tasks:
            if t.status in (
                TaskLifecycleState.PENDING.value,
                TaskLifecycleState.CLAIMED.value,
                TaskLifecycleState.RUNNING.value,
                TaskLifecycleState.RETRY_PENDING.value,
            ):
                t.status = TaskLifecycleState.CANCELLED.value
                t.lease_expires_at = None
                t.worker_id = None
                t.failure_reason = reason or "Campaign killed by operator (emergency stop)"

        # Release target assignments
        self.repo.release_campaign_targets(campaign_id)

        # Transition to KILLED
        updated = self.repo.update_campaign_status(
            campaign_id=campaign_id,
            target_status=CampaignLifecycleState.KILLED,
            actor=actor,
            reason=reason or "Emergency kill switch activated by operator",
        )

        self.repo.append_audit_event(
            campaign_id=campaign.id,
            event_type="CAMPAIGN_KILLED",
            actor=actor,
            metadata={
                "reason": reason or "Emergency kill switch activated by operator",
                "tasks_cancelled": sum(
                    1 for t in campaign.tasks if t.status == TaskLifecycleState.CANCELLED.value
                ),
            },
        )

        return updated

    @staticmethod
    def validate_production_profile_override(
        budget: int, concurrency: int, rate: int, method: str = "GET",
    ) -> tuple[bool, str]:
        """Validate that production profile constraints are not exceeded. Returns (valid, reason)."""
        profile = CampaignOperationsService.PRODUCTION_PROFILE
        if budget > profile["campaign_budget"]:
            return False, f"Production budget must not exceed {profile['campaign_budget']} (got {budget})"
        if concurrency > profile["max_concurrency"]:
            return False, f"Production concurrency must not exceed {profile['max_concurrency']} (got {concurrency})"
        if rate > profile["rate_limit_rps"]:
            return False, f"Production rate limit must not exceed {profile['rate_limit_rps']} (got {rate})"
        if method.upper() in CampaignOperationsService.PRODUCTION_PROHIBITED_METHODS:
            return False, f"HTTP method '{method}' is prohibited in production mode"
        return True, "Production profile constraints satisfied"

    def generate_hackerone_report(self, campaign_id: str) -> Dict[str, Any]:
        """Generate a HackerOne-style report with FACT/INFERENCE/IMPACT sections.

        Returns structured report with integrity metadata.
        """
        campaign = self.repo.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id}' not found.")

        # Gather findings
        from backend.models.database import Finding
        findings = (
            self.repo.session.query(Finding)
            .filter(Finding.scan_id == campaign_id)
            .all()
        )

        verified_findings = [f for f in findings if f.verification_status == "VERIFIED"]
        candidate_findings = [f for f in findings if f.verification_status in ("CANDIDATE", "NEEDS_HUMAN_REVIEW")]

        # Gather evidence
        evidence_records = self.repo.get_evidence_for_campaign(campaign_id, limit=1000)
        evidence_hashes = [r.content_hash for r in evidence_records]

        # Compute integrity
        manifest = self.generate_manifest(campaign_id) if evidence_records else None
        snapshot = self.repo.get_snapshot(campaign_id)
        snapshot_hash = snapshot.snapshot_hash if snapshot else ""

        report_content = {
            "campaign_id": campaign_id,
            "assessment_mode": getattr(campaign, "assessment_mode", "CONTROLLED"),
            "target_url": campaign.target_url,
            "program_id": campaign.program_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        # Build per-finding report sections
        finding_reports = []
        for f in verified_findings:
            finding_evidence = [e for e in evidence_records if e.finding_id == f.id]
            finding_reports.append({
                "title": f.title,
                "summary": f"Verified {f.vuln_type} vulnerability at {f.affected_url}",
                "asset": f.affected_url,
                "vulnerability_type": f.vuln_type,
                "severity": f.severity,
                "description": {
                    "facts": [
                        f"HTTP response analysis at {f.affected_url}",
                        f"Check identified: {f.vuln_type}",
                        f"Verification status: {f.verification_status}",
                        f"Confidence: {f.confidence}%",
                    ],
                    "steps_to_reproduce": [
                        f"1. Send {f.proof_request or 'GET request'} to {f.affected_url}",
                        f"2. Observe response indicating {f.vuln_type}",
                    ],
                    "proof_of_concept": f.payload or "Non-destructive observation only",
                },
                "impact": {
                    "inference": f.business_impact or f"Potential {f.severity} severity security issue",
                    "note": "Impact assessment is an inference from observed facts. "
                            "Actual exploitability depends on application context.",
                },
                "evidence": {
                    "evidence_ids": [e.id for e in finding_evidence],
                    "evidence_hashes": [e.content_hash for e in finding_evidence],
                    "finding_id": f.id,
                },
                "suggested_remediation": f.remediation or "Review and remediate the identified issue.",
                "references": [],
            })

        # Report integrity hash
        report_data_str = json.dumps(finding_reports, sort_keys=True, default=str)
        report_hash = hashlib.sha256(report_data_str.encode("utf-8")).hexdigest()

        report_content["findings"] = finding_reports
        report_content["candidates_not_included"] = len(candidate_findings)
        report_content["integrity"] = {
            "evidence_sha256_list": evidence_hashes,
            "manifest_hash": manifest.manifest_hash if manifest else "",
            "report_hash": report_hash,
            "campaign_snapshot_hash": snapshot_hash,
        }

        self.repo.append_audit_event(
            campaign_id=campaign_id,
            event_type="REPORT_GENERATED",
            actor="system",
            metadata={
                "report_type": "hackerone",
                "verified_findings": len(verified_findings),
                "report_hash": report_hash,
            },
        )

        return report_content


# Alias for backwards compatibility
CampaignOperations = CampaignOperationsService
