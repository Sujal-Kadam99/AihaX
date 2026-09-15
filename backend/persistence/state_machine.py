"""AihaX Phase 8 — Campaign & Task Lifecycle State Machines.

Deterministic state machines enforcing:
- Campaign lifecycle: DRAFT -> AUTHORIZED -> QUEUED -> RUNNING -> PAUSED -> COMPLETED
  Failure paths: RUNNING -> FAILED, RUNNING -> CANCELLED, QUEUED -> CANCELLED, PAUSED -> CANCELLED
- Task lifecycle: PENDING -> CLAIMED -> RUNNING -> COMPLETED
  Failure paths: RUNNING -> RETRY_PENDING, RUNNING -> FAILED, PENDING -> CANCELLED, CLAIMED -> CANCELLED
- State transition audit logging & fail-closed validation
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, Set, Tuple


class CampaignLifecycleState(str, Enum):
    DRAFT = "DRAFT"
    AUTHORIZED = "AUTHORIZED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    KILLED = "KILLED"  # Phase 16: Emergency kill switch — terminal


class TaskLifecycleState(str, Enum):
    PENDING = "PENDING"
    CLAIMED = "CLAIMED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    RETRY_PENDING = "RETRY_PENDING"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


# Allowed state transitions for Campaign
VALID_CAMPAIGN_TRANSITIONS: Dict[CampaignLifecycleState, Set[CampaignLifecycleState]] = {
    CampaignLifecycleState.DRAFT: {CampaignLifecycleState.AUTHORIZED, CampaignLifecycleState.CANCELLED, CampaignLifecycleState.KILLED},
    CampaignLifecycleState.AUTHORIZED: {CampaignLifecycleState.QUEUED, CampaignLifecycleState.RUNNING, CampaignLifecycleState.CANCELLED, CampaignLifecycleState.KILLED},
    CampaignLifecycleState.QUEUED: {CampaignLifecycleState.RUNNING, CampaignLifecycleState.CANCELLED, CampaignLifecycleState.KILLED},
    CampaignLifecycleState.RUNNING: {
        CampaignLifecycleState.PAUSED,
        CampaignLifecycleState.COMPLETED,
        CampaignLifecycleState.FAILED,
        CampaignLifecycleState.CANCELLED,
        CampaignLifecycleState.KILLED,
    },
    CampaignLifecycleState.PAUSED: {
        CampaignLifecycleState.RUNNING,
        CampaignLifecycleState.CANCELLED,
        CampaignLifecycleState.COMPLETED,
        CampaignLifecycleState.KILLED,
    },
    CampaignLifecycleState.COMPLETED: set(),  # Terminal
    CampaignLifecycleState.FAILED: set(),     # Terminal
    CampaignLifecycleState.CANCELLED: set(),  # Terminal
    CampaignLifecycleState.KILLED: set(),     # Terminal — Phase 16 kill switch
}


# Allowed state transitions for ExecutionTask
VALID_TASK_TRANSITIONS: Dict[TaskLifecycleState, Set[TaskLifecycleState]] = {
    TaskLifecycleState.PENDING: {TaskLifecycleState.CLAIMED, TaskLifecycleState.CANCELLED},
    TaskLifecycleState.CLAIMED: {
        TaskLifecycleState.RUNNING,
        TaskLifecycleState.COMPLETED,
        TaskLifecycleState.RETRY_PENDING,
        TaskLifecycleState.FAILED,
        TaskLifecycleState.PENDING,
        TaskLifecycleState.CANCELLED,
    },
    TaskLifecycleState.RUNNING: {
        TaskLifecycleState.COMPLETED,
        TaskLifecycleState.RETRY_PENDING,
        TaskLifecycleState.FAILED,
        TaskLifecycleState.CANCELLED,
    },
    TaskLifecycleState.RETRY_PENDING: {
        TaskLifecycleState.CLAIMED,
        TaskLifecycleState.PENDING,
        TaskLifecycleState.FAILED,
        TaskLifecycleState.CANCELLED,
    },
    TaskLifecycleState.COMPLETED: set(),
    TaskLifecycleState.FAILED: set(),
    TaskLifecycleState.CANCELLED: set(),
}


class InvalidStateTransitionError(Exception):
    """Raised when an illegal lifecycle state transition is attempted."""

    def __init__(self, entity_type: str, current_state: str, target_state: str, reason: str = "") -> None:
        self.entity_type = entity_type
        self.current_state = current_state
        self.target_state = target_state
        msg = f"Invalid {entity_type} state transition: '{current_state}' -> '{target_state}'."
        if reason:
            msg += f" Reason: {reason}"
        super().__init__(msg)


class CampaignStateMachine:
    """Validator for campaign state transitions."""

    @staticmethod
    def validate_transition(current: str | CampaignLifecycleState, target: str | CampaignLifecycleState) -> bool:
        curr_enum = CampaignLifecycleState(current) if isinstance(current, str) else current
        target_enum = CampaignLifecycleState(target) if isinstance(target, str) else target

        if target_enum in VALID_CAMPAIGN_TRANSITIONS.get(curr_enum, set()):
            return True
        return False

    @classmethod
    def transition_or_raise(cls, current: str | CampaignLifecycleState, target: str | CampaignLifecycleState) -> CampaignLifecycleState:
        curr_enum = CampaignLifecycleState(current) if isinstance(current, str) else current
        target_enum = CampaignLifecycleState(target) if isinstance(target, str) else target

        # Idempotent cancellation/kill is safe and terminal
        if curr_enum == CampaignLifecycleState.CANCELLED and target_enum == CampaignLifecycleState.CANCELLED:
            return CampaignLifecycleState.CANCELLED
        if curr_enum == CampaignLifecycleState.KILLED and target_enum == CampaignLifecycleState.KILLED:
            return CampaignLifecycleState.KILLED

        if not cls.validate_transition(curr_enum, target_enum):
            valid = [s.value for s in VALID_CAMPAIGN_TRANSITIONS.get(curr_enum, set())]
            raise InvalidStateTransitionError(
                "Campaign",
                curr_enum.value,
                target_enum.value,
                f"Valid next states from '{curr_enum.value}' are: {valid}",
            )
        return target_enum


class TaskStateMachine:
    """Validator for task state transitions."""

    @staticmethod
    def validate_transition(current: str | TaskLifecycleState, target: str | TaskLifecycleState) -> bool:
        curr_enum = TaskLifecycleState(current) if isinstance(current, str) else current
        target_enum = TaskLifecycleState(target) if isinstance(target, str) else target

        if target_enum in VALID_TASK_TRANSITIONS.get(curr_enum, set()):
            return True
        return False

    @classmethod
    def transition_or_raise(cls, current: str | TaskLifecycleState, target: str | TaskLifecycleState) -> TaskLifecycleState:
        curr_enum = TaskLifecycleState(current) if isinstance(current, str) else current
        target_enum = TaskLifecycleState(target) if isinstance(target, str) else target

        if not cls.validate_transition(curr_enum, target_enum):
            valid = [s.value for s in VALID_TASK_TRANSITIONS.get(curr_enum, set())]
            raise InvalidStateTransitionError(
                "ExecutionTask",
                curr_enum.value,
                target_enum.value,
                f"Valid next states from '{curr_enum.value}' are: {valid}",
            )
        return target_enum
