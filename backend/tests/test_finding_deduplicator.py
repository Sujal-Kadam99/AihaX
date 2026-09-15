"""Tests for Finding Deduplication, Confidence Scoring, and Evidence Hashing."""

import json
import pytest
from backend.models.database import Finding
from backend.services.finding_deduplicator import (
    ConfidenceLevel,
    DeterministicConfidenceScorer,
    EvidenceHasher,
    FindingDeduplicator,
    FindingLifecycleState,
    can_transition,
    normalize_endpoint_for_fingerprint,
    normalize_param_location,
)


def test_fingerprint_generation_is_stable():
    fp1 = FindingDeduplicator.generate_fingerprint(
        check_id="C023_SQL_Injection",
        affected_url="https://example.com/api/users?id=1",
        affected_param="id",
        vuln_category="Injection",
    )
    fp2 = FindingDeduplicator.generate_fingerprint(
        check_id="C023_SQL_Injection",
        affected_url="https://example.com/api/users/?id=2",  # Trailing slash variation
        affected_param="id",
        vuln_category="Injection",
    )
    # Both point to the same endpoint and parameter for C023
    assert fp1 == fp2


def test_fingerprint_preserves_distinct_boundaries():
    fp_root = FindingDeduplicator.generate_fingerprint(
        check_id="C023_SQL_Injection",
        affected_url="https://example.com/api/users",
        affected_param="id",
    )
    fp_subdomain = FindingDeduplicator.generate_fingerprint(
        check_id="C023_SQL_Injection",
        affected_url="https://api.example.com/api/users",
        affected_param="id",
    )
    # Distinct hostnames must NOT be merged
    assert fp_root != fp_subdomain


def test_deduplicate_multiple_candidates_same_endpoint():
    f1 = Finding(
        id="f1",
        scan_id="scan-1",
        agent_id=3,
        title="SQL Injection",
        vuln_type="C023_SQL_Injection",
        category="Injection",
        severity="high",
        affected_url="https://example.com/search?q=test1",
        affected_param="q",
        payload="' OR 1=1--",
        confidence=80,
        verdict="Inconclusive",
        evidence_ids=json.dumps(["ev-1"]),
        request_ids=json.dumps(["req-1"]),
    )
    f2 = Finding(
        id="f2",
        scan_id="scan-1",
        agent_id=3,
        title="SQL Injection",
        vuln_type="C023_SQL_Injection",
        category="Injection",
        severity="high",
        affected_url="https://example.com/search?q=test2",
        affected_param="q",
        payload="' UNION SELECT null--",
        confidence=95,
        verdict="Verified",
        evidence_ids=json.dumps(["ev-2"]),
        request_ids=json.dumps(["req-2"]),
    )

    groups = FindingDeduplicator.deduplicate_findings([f1, f2])
    assert len(groups) == 1
    group = groups[0]
    assert group.duplicate_count == 2
    # Verified and higher confidence f2 must be chosen as primary
    assert group.primary_finding.id == "f2"
    assert "ev-1" in group.combined_evidence_ids
    assert "ev-2" in group.combined_evidence_ids
    assert "' OR 1=1--" in group.combined_payloads
    assert "' UNION SELECT null--" in group.combined_payloads


def test_deterministic_confidence_scoring():
    # Direct reproduction + baseline differential + math canary = 100 CERTAIN
    score1, level1 = DeterministicConfidenceScorer.calculate_confidence(
        reproduced_successfully=True,
        baseline_differential_verified=True,
        math_canary_verified=True,
    )
    assert score1 == 100
    assert level1 == ConfidenceLevel.CERTAIN

    # Inconclusive heuristic penalty
    score2, level2 = DeterministicConfidenceScorer.calculate_confidence(
        reproduced_successfully=False,
        inconclusive_heuristic=True,
        missing_baseline=True,
    )
    assert score2 <= 30
    assert level2 == ConfidenceLevel.LOW


def test_evidence_hash_immutability():
    ev_hash = EvidenceHasher.compute_evidence_hash(
        vuln_type="C003_Sensitive_Files_Exposure",
        affected_url="https://example.com/.env",
        affected_param=None,
        payload=None,
        proof_request="GET /.env HTTP/1.1",
        proof_response="DB_PASSWORD=secret",
        reason_code="REPRODUCED_SUCCESSFULLY",
    )
    assert isinstance(ev_hash, str) and len(ev_hash) == 64

    # Verification passes with original data
    finding = Finding(
        vuln_type="C003_Sensitive_Files_Exposure",
        affected_url="https://example.com/.env",
        affected_param=None,
        payload=None,
        proof_request="GET /.env HTTP/1.1",
        proof_response="DB_PASSWORD=secret",
        verification_reason_code="REPRODUCED_SUCCESSFULLY",
    )
    assert EvidenceHasher.verify_evidence_integrity(finding, ev_hash) is True

    # Mutated evidence fails verification
    finding.proof_response = "TAMPERED_BODY"
    assert EvidenceHasher.verify_evidence_integrity(finding, ev_hash) is False


def test_finding_lifecycle_state_machine():
    assert can_transition(FindingLifecycleState.DISCOVERED, FindingLifecycleState.CANDIDATE) is True
    assert can_transition(FindingLifecycleState.CANDIDATE, FindingLifecycleState.VERIFYING) is True
    assert can_transition(FindingLifecycleState.VERIFYING, FindingLifecycleState.VERIFIED) is True
    assert can_transition(FindingLifecycleState.VERIFIED, FindingLifecycleState.DEDUPLICATED) is True
    assert can_transition(FindingLifecycleState.DEDUPLICATED, FindingLifecycleState.REPORTABLE) is True

    # Invalid transitions
    assert can_transition(FindingLifecycleState.DISCOVERED, FindingLifecycleState.REPORTABLE) is False
    assert can_transition(FindingLifecycleState.CANDIDATE, FindingLifecycleState.VERIFIED) is False
    assert can_transition(FindingLifecycleState.REJECTED, FindingLifecycleState.REPORTABLE) is False
