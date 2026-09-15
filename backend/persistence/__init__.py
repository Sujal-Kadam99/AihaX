"""AihaX Phase 8 — Persistence Package."""

from backend.persistence.models import (
    AuditTrailEvent,
    AuthorizationRecord,
    Campaign,
    CampaignSnapshot,
    CampaignTarget,
    EvidenceRecord,
    ExecutionTask,
)
from backend.persistence.repository import CampaignRepository
from backend.persistence.state_machine import (
    CampaignLifecycleState,
    CampaignStateMachine,
    InvalidStateTransitionError,
    TaskLifecycleState,
    TaskStateMachine,
)

__all__ = [
    "Campaign",
    "CampaignTarget",
    "ExecutionTask",
    "AuthorizationRecord",
    "EvidenceRecord",
    "AuditTrailEvent",
    "CampaignSnapshot",
    "CampaignRepository",
    "CampaignLifecycleState",
    "TaskLifecycleState",
    "CampaignStateMachine",
    "TaskStateMachine",
    "InvalidStateTransitionError",
]
