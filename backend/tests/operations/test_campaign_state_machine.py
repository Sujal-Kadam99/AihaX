"""AihaX Phase 8 — Campaign State Machine Unit Tests."""

import pytest
from backend.persistence.state_machine import (
    CampaignLifecycleState,
    CampaignStateMachine,
    InvalidStateTransitionError,
    TaskLifecycleState,
    TaskStateMachine,
)


def test_valid_campaign_transitions():
    valid_paths = [
        (CampaignLifecycleState.DRAFT, CampaignLifecycleState.AUTHORIZED),
        (CampaignLifecycleState.AUTHORIZED, CampaignLifecycleState.QUEUED),
        (CampaignLifecycleState.AUTHORIZED, CampaignLifecycleState.RUNNING),
        (CampaignLifecycleState.QUEUED, CampaignLifecycleState.RUNNING),
        (CampaignLifecycleState.RUNNING, CampaignLifecycleState.PAUSED),
        (CampaignLifecycleState.PAUSED, CampaignLifecycleState.RUNNING),
        (CampaignLifecycleState.RUNNING, CampaignLifecycleState.COMPLETED),
        (CampaignLifecycleState.RUNNING, CampaignLifecycleState.FAILED),
        (CampaignLifecycleState.RUNNING, CampaignLifecycleState.CANCELLED),
        (CampaignLifecycleState.PAUSED, CampaignLifecycleState.CANCELLED),
        (CampaignLifecycleState.DRAFT, CampaignLifecycleState.CANCELLED),
    ]
    for curr, target in valid_paths:
        assert CampaignStateMachine.validate_transition(curr, target) is True
        assert CampaignStateMachine.transition_or_raise(curr, target) == target


def test_invalid_campaign_transitions_raise():
    invalid_paths = [
        (CampaignLifecycleState.DRAFT, CampaignLifecycleState.RUNNING),
        (CampaignLifecycleState.DRAFT, CampaignLifecycleState.COMPLETED),
        (CampaignLifecycleState.COMPLETED, CampaignLifecycleState.RUNNING),
        (CampaignLifecycleState.FAILED, CampaignLifecycleState.RUNNING),
        (CampaignLifecycleState.CANCELLED, CampaignLifecycleState.RUNNING),
    ]
    for curr, target in invalid_paths:
        assert CampaignStateMachine.validate_transition(curr, target) is False
        with pytest.raises(InvalidStateTransitionError):
            CampaignStateMachine.transition_or_raise(curr, target)


def test_task_state_machine_transitions():
    assert TaskStateMachine.validate_transition(TaskLifecycleState.PENDING, TaskLifecycleState.CLAIMED) is True
    assert TaskStateMachine.validate_transition(TaskLifecycleState.CLAIMED, TaskLifecycleState.RUNNING) is True
    assert TaskStateMachine.validate_transition(TaskLifecycleState.RUNNING, TaskLifecycleState.COMPLETED) is True
    assert TaskStateMachine.validate_transition(TaskLifecycleState.RUNNING, TaskLifecycleState.RETRY_PENDING) is True
    assert TaskStateMachine.validate_transition(TaskLifecycleState.RETRY_PENDING, TaskLifecycleState.PENDING) is True

    # Invalid jump
    assert TaskStateMachine.validate_transition(TaskLifecycleState.PENDING, TaskLifecycleState.COMPLETED) is False
    with pytest.raises(InvalidStateTransitionError):
        TaskStateMachine.transition_or_raise(TaskLifecycleState.PENDING, TaskLifecycleState.COMPLETED)
