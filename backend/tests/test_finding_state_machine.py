"""Tests for Finding Lifecycle State Machine and Immutability."""

import pytest
from backend.models.database import Finding
from backend.services.finding_deduplicator import (
    EvidenceHasher,
    FindingLifecycleState,
    can_transition,
)


def test_complete_valid_lifecycle_transitions():
    state = FindingLifecycleState.DISCOVERED
    assert can_transition(state, FindingLifecycleState.CANDIDATE) is True

    state = FindingLifecycleState.CANDIDATE
    assert can_transition(state, FindingLifecycleState.VERIFYING) is True

    state = FindingLifecycleState.VERIFYING
    assert can_transition(state, FindingLifecycleState.VERIFIED) is True

    state = FindingLifecycleState.VERIFIED
    assert can_transition(state, FindingLifecycleState.DEDUPLICATED) is True

    state = FindingLifecycleState.DEDUPLICATED
    assert can_transition(state, FindingLifecycleState.REPORTABLE) is True


def test_rejection_and_inconclusive_transitions():
    assert can_transition(FindingLifecycleState.CANDIDATE, FindingLifecycleState.REJECTED) is True
    assert can_transition(FindingLifecycleState.CANDIDATE, FindingLifecycleState.INCONCLUSIVE) is True
    assert can_transition(FindingLifecycleState.VERIFYING, FindingLifecycleState.REJECTED) is True
    assert can_transition(FindingLifecycleState.VERIFYING, FindingLifecycleState.INCONCLUSIVE) is True


def test_invalid_bypass_transitions():
    # Cannot jump directly from DISCOVERED to VERIFIED or REPORTABLE
    assert can_transition(FindingLifecycleState.DISCOVERED, FindingLifecycleState.VERIFIED) is False
    assert can_transition(FindingLifecycleState.DISCOVERED, FindingLifecycleState.REPORTABLE) is False

    # Cannot jump directly from CANDIDATE to REPORTABLE
    assert can_transition(FindingLifecycleState.CANDIDATE, FindingLifecycleState.REPORTABLE) is False

    # REJECTED or INCONCLUSIVE cannot become REPORTABLE
    assert can_transition(FindingLifecycleState.REJECTED, FindingLifecycleState.REPORTABLE) is False
    assert can_transition(FindingLifecycleState.INCONCLUSIVE, FindingLifecycleState.REPORTABLE) is False


def test_verified_finding_evidence_immutability():
    f = Finding(
        vuln_type="C023_SQL_Injection",
        affected_url="https://example.com/api/items?id=1",
        affected_param="id",
        payload="' OR 1=1--",
        proof_request="GET /api/items?id=1' HTTP/1.1",
        proof_response="You have an error in your SQL syntax",
        verification_reason_code="REPRODUCED_SUCCESSFULLY",
    )

    ev_hash = EvidenceHasher.compute_evidence_hash(
        vuln_type=str(f.vuln_type),
        affected_url=str(f.affected_url),
        affected_param=f.affected_param,
        payload=f.payload,
        proof_request=f.proof_request,
        proof_response=f.proof_response,
        reason_code=f.verification_reason_code,
    )

    # Initial integrity check passes
    assert EvidenceHasher.verify_evidence_integrity(f, ev_hash) is True

    # Tampering with proof_request breaks integrity
    f.proof_request = "GET /api/items?id=2 HTTP/1.1"
    assert EvidenceHasher.verify_evidence_integrity(f, ev_hash) is False
