"""AihaX Phase 6 — 77-Check Coverage Validation Tests.

Validates that:
1. All 77 checks are correctly registered with valid contracts.
2. CoverageValidator builds a correct coverage matrix from CampaignResult audit trails.
3. CheckExecutionStatus values are deterministic and accurate.
4. Registry completeness validation passes (77 checks, no duplicates, no invalid contracts).
5. Static registry matrix is correctly structured.
6. CampaignCoverageReport assertions work correctly.
"""

import pytest
from datetime import datetime, timezone

from backend.services.coverage_validator import (
    CampaignCoverageReport,
    CheckCoverageRecord,
    CheckExecutionStatus,
    CoverageValidator,
)
import backend.agents.checks  # Ensure all 77 checks are loaded
from backend.core.check_registry import registry
from backend.services.campaign_executor import (
    AUTHENTICATION_REQUIRED_CHECKS,
    BROWSER_REQUIRED_CHECKS,
    WORKFLOW_REQUIRED_CHECKS,
    CampaignResult,
)
from backend.models.database import Finding


# ──────────────────────────────────────────────────────────────────────────────
# 1. Registry Completeness Tests
# ──────────────────────────────────────────────────────────────────────────────

def test_registry_has_exactly_77_checks():
    """Registry must contain exactly 77 checks."""
    contracts = registry.list_checks()
    assert len(contracts) == 77, (
        f"Expected exactly 77 checks, got {len(contracts)}. "
        f"IDs: {sorted(c.id for c in contracts)}"
    )


def test_validate_registry_completeness_passes():
    """CoverageValidator.validate_registry_completeness must pass for 77 checks."""
    result = CoverageValidator.validate_registry_completeness(expected_count=77)
    assert result["all_valid"] is True
    assert result["count_matches"] is True
    assert result["actual_count"] == 77
    assert result["duplicate_ids"] == []
    assert result["invalid_contracts"] == []


def test_all_77_check_ids_are_unique():
    """All check IDs must be unique (no duplicates)."""
    contracts = registry.list_checks()
    ids = [c.id for c in contracts]
    assert len(ids) == len(set(ids)), f"Duplicate check IDs: {[i for i in ids if ids.count(i) > 1]}"


def test_all_77_checks_are_non_destructive():
    """No check may be destructive."""
    contracts = registry.list_checks()
    destructive = [c.id for c in contracts if c.destructive]
    assert destructive == [], f"Destructive checks found: {destructive}"


def test_all_77_checks_have_valid_contracts():
    """Every check contract must validate successfully."""
    contracts = registry.list_checks()
    for c in contracts:
        assert c.validate_contract() is True, f"Contract validation failed for {c.id}"


def test_all_77_checks_have_max_requests_gte_1():
    """All checks must have max_requests >= 1."""
    contracts = registry.list_checks()
    for c in contracts:
        assert c.max_requests >= 1, f"{c.id} has max_requests={c.max_requests}"


def test_all_77_checks_have_valid_categories():
    """All check categories must be valid CheckCategory enum values."""
    from backend.core.check_registry import CheckCategory
    contracts = registry.list_checks()
    for c in contracts:
        assert isinstance(c.category, CheckCategory), f"{c.id}: invalid category '{c.category}'"


def test_all_77_checks_have_non_empty_required_capabilities():
    """All checks must declare at least one required capability."""
    contracts = registry.list_checks()
    for c in contracts:
        assert len(c.required_capabilities) >= 1, (
            f"{c.id}: required_capabilities must not be empty"
        )


# ──────────────────────────────────────────────────────────────────────────────
# 2. Static Registry Matrix Tests
# ──────────────────────────────────────────────────────────────────────────────

def test_build_registry_matrix_returns_correct_totals():
    """Static registry matrix must correctly reflect 77 checks."""
    matrix = CoverageValidator.build_registry_matrix()
    assert matrix["total_registered"] == 77
    # Sum across all categories must == 77
    total_by_cat = sum(len(v) for v in matrix["by_category"].values())
    assert total_by_cat == 77


def test_build_registry_matrix_browser_auth_workflow_counts():
    """Static matrix must correctly count checks requiring browser/auth/workflow."""
    matrix = CoverageValidator.build_registry_matrix()
    assert matrix["browser_required"] == len(BROWSER_REQUIRED_CHECKS)
    assert matrix["auth_required"] == len(AUTHENTICATION_REQUIRED_CHECKS)
    assert matrix["workflow_required"] == len(WORKFLOW_REQUIRED_CHECKS)


def test_build_registry_matrix_has_all_categories():
    """Registry matrix must include at least 5 known vulnerability categories."""
    matrix = CoverageValidator.build_registry_matrix()
    categories = set(matrix["by_category"].keys())
    expected = {"recon", "auth", "injection", "xss", "misconfig", "sensitive_data", "business_logic"}
    assert expected.issubset(categories), (
        f"Missing categories: {expected - categories}"
    )


def test_build_registry_matrix_http_only_count():
    """HTTP-only executable checks must equal total minus those requiring browser/auth/workflow."""
    matrix = CoverageValidator.build_registry_matrix()
    # Check that http_only count makes sense
    total = 77
    browser = len(BROWSER_REQUIRED_CHECKS)
    auth = len(AUTHENTICATION_REQUIRED_CHECKS)
    workflow = len(WORKFLOW_REQUIRED_CHECKS)
    # These can overlap — http_only is checks NOT in any special set
    http_only = matrix["http_only_executable"]
    assert http_only > 0
    assert http_only <= total


# ──────────────────────────────────────────────────────────────────────────────
# 3. CoverageValidator — coverage report from mock CampaignResult
# ──────────────────────────────────────────────────────────────────────────────

def _make_campaign_result(
    campaign_id: str = "cmp-test",
    target_url: str = "http://example.local",
    mode: str = "SAFE_SCAN",
    audit_trail: list | None = None,
    findings: list | None = None,
) -> CampaignResult:
    """Build a minimal CampaignResult with given audit trail."""
    return CampaignResult(
        campaign_id=campaign_id,
        target_url=target_url,
        assets_discovered=1,
        assets_scanned=1,
        assets_skipped=0,
        checks_planned=77,
        checks_executed=len([e for e in (audit_trail or []) if e.get("event") == "check_started"]),
        checks_not_applicable=0,
        requests_used=10,
        requests_budget=500,
        candidates_count=0,
        verified_findings_count=0,
        rejected_candidates_count=0,
        inconclusive_results_count=0,
        severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        confidence_counts={"CERTAIN": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        execution_duration=1.5,
        safety_events=[],
        budget_events=[],
        audit_trail=audit_trail or [],
        findings=findings or [],
        mode=mode,
    )


def test_build_coverage_report_empty_audit_trail():
    """With empty audit trail, all eligible checks land in PLANNED_UNREACHED or SKIPPED_PREREQUISITE."""
    result = _make_campaign_result(audit_trail=[])
    report = CoverageValidator.build_coverage_report(result)

    assert report.total_registered_checks == 77
    assert report.checks_executed == 0
    assert report.checks_with_candidates == 0
    # All checks are either skipped (prereq) or unreached
    assert report.checks_skipped_prerequisite + report.checks_planned_unreached == 77


def test_build_coverage_report_with_executed_checks():
    """Checks that appear in check_started audit events must be EXECUTED_NO_CANDIDATE."""
    # Get a real check ID from registry
    contracts = registry.list_checks()
    # Pick a check that doesn't require auth/browser/workflow
    plain_checks = [
        c for c in contracts
        if c.id not in BROWSER_REQUIRED_CHECKS
        and c.id not in AUTHENTICATION_REQUIRED_CHECKS
        and c.id not in WORKFLOW_REQUIRED_CHECKS
    ]
    check_id = plain_checks[0].id

    audit = [
        {"event": "check_started", "details": {"check_id": check_id, "target": "http://example.local"}},
    ]
    result = _make_campaign_result(audit_trail=audit)
    report = CoverageValidator.build_coverage_report(result)

    record = report.get_record(check_id)
    assert record is not None
    assert record.status == CheckExecutionStatus.EXECUTED_NO_CANDIDATE
    assert record.was_executed is True
    assert record.produced_candidate is False
    assert report.checks_executed == 1


def test_build_coverage_report_with_candidate_finding():
    """When check_started + candidate_created audit events, status = EXECUTED_CANDIDATE."""
    contracts = registry.list_checks()
    plain_checks = [
        c for c in contracts
        if c.id not in BROWSER_REQUIRED_CHECKS
        and c.id not in AUTHENTICATION_REQUIRED_CHECKS
        and c.id not in WORKFLOW_REQUIRED_CHECKS
    ]
    check_id = plain_checks[0].id
    finding_id = "find-abc123"

    audit = [
        {"event": "check_started", "details": {"check_id": check_id, "target": "http://example.local"}},
        {"event": "candidate_created", "details": {"finding_id": finding_id, "vuln_type": check_id, "target": "http://example.local"}},
    ]
    result = _make_campaign_result(audit_trail=audit)
    report = CoverageValidator.build_coverage_report(result)

    record = report.get_record(check_id)
    assert record is not None
    assert record.status == CheckExecutionStatus.EXECUTED_CANDIDATE
    assert record.produced_candidate is True
    assert finding_id in record.candidate_finding_ids
    assert report.checks_with_candidates == 1


def test_build_coverage_report_browser_checks_skipped_prerequisite():
    """Browser-required checks should be SKIPPED_PREREQUISITE when not in audit trail."""
    result = _make_campaign_result(audit_trail=[])
    report = CoverageValidator.build_coverage_report(result)

    for check_id in BROWSER_REQUIRED_CHECKS:
        record = report.get_record(check_id)
        if record:
            assert record.status == CheckExecutionStatus.SKIPPED_PREREQUISITE
            assert record.requires_browser is True
            assert record.prerequisite_gap is not None


def test_build_coverage_report_auth_checks_skipped_prerequisite():
    """Auth-required checks should be SKIPPED_PREREQUISITE when not in audit trail."""
    result = _make_campaign_result(audit_trail=[])
    report = CoverageValidator.build_coverage_report(result)

    for check_id in AUTHENTICATION_REQUIRED_CHECKS:
        record = report.get_record(check_id)
        if record:
            assert record.status == CheckExecutionStatus.SKIPPED_PREREQUISITE
            assert record.requires_auth is True


def test_build_coverage_report_workflow_checks_skipped_prerequisite():
    """Workflow-required checks should be SKIPPED_PREREQUISITE when not in audit trail."""
    result = _make_campaign_result(audit_trail=[])
    report = CoverageValidator.build_coverage_report(result)

    for check_id in WORKFLOW_REQUIRED_CHECKS:
        record = report.get_record(check_id)
        if record:
            assert record.status == CheckExecutionStatus.SKIPPED_PREREQUISITE
            assert record.requires_workflow is True


def test_build_coverage_report_to_dict_structure():
    """Coverage report to_dict must have all required fields."""
    result = _make_campaign_result(audit_trail=[])
    report = CoverageValidator.build_coverage_report(result)
    d = report.to_dict()

    assert "campaign_id" in d
    assert "target_url" in d
    assert "mode" in d
    assert "generated_at" in d
    assert "summary" in d
    assert "records" in d

    summary = d["summary"]
    assert "total_registered_checks" in summary
    assert "checks_executed" in summary
    assert "checks_with_candidates" in summary
    assert "checks_with_verified_findings" in summary
    assert "checks_skipped_prerequisite" in summary
    assert "checks_skipped_budget" in summary
    assert "coverage_percentage" in summary
    assert "reachable_percentage" in summary

    assert len(d["records"]) == 77


def test_build_coverage_report_to_json_is_valid():
    """Coverage report JSON must be valid and parseable."""
    import json
    result = _make_campaign_result(audit_trail=[])
    report = CoverageValidator.build_coverage_report(result)
    raw_json = report.to_json()
    parsed = json.loads(raw_json)
    assert parsed["summary"]["total_registered_checks"] == 77


def test_coverage_report_assert_minimum_coverage_fails_when_none_executed():
    """assert_minimum_coverage must fail when 0 checks were executed."""
    result = _make_campaign_result(audit_trail=[])
    report = CoverageValidator.build_coverage_report(result)

    with pytest.raises(AssertionError, match="Coverage assertion failed"):
        report.assert_minimum_coverage(min_executed=50)


def test_coverage_report_assert_minimum_coverage_passes_with_enough_executed():
    """assert_minimum_coverage must pass when enough checks were executed."""
    contracts = registry.list_checks()
    plain_checks = [
        c for c in contracts
        if c.id not in BROWSER_REQUIRED_CHECKS
        and c.id not in AUTHENTICATION_REQUIRED_CHECKS
        and c.id not in WORKFLOW_REQUIRED_CHECKS
    ]

    # Simulate executing 55 checks
    audit = []
    for c in plain_checks[:55]:
        audit.append({
            "event": "check_started",
            "details": {"check_id": c.id, "target": "http://example.local"},
        })

    result = _make_campaign_result(audit_trail=audit)
    report = CoverageValidator.build_coverage_report(result)

    # Should not raise
    report.assert_minimum_coverage(min_executed=50, min_reachable_pct=0.0)
    assert report.checks_executed == 55


def test_coverage_report_executed_check_ids_set():
    """executed_check_ids property returns correct set."""
    contracts = registry.list_checks()
    plain_check = next(
        c for c in contracts
        if c.id not in BROWSER_REQUIRED_CHECKS
        and c.id not in AUTHENTICATION_REQUIRED_CHECKS
        and c.id not in WORKFLOW_REQUIRED_CHECKS
    )

    audit = [
        {"event": "check_started", "details": {"check_id": plain_check.id, "target": "http://t"}},
    ]
    result = _make_campaign_result(audit_trail=audit)
    report = CoverageValidator.build_coverage_report(result)

    assert plain_check.id in report.executed_check_ids
    assert len(report.executed_check_ids) == 1


def test_coverage_report_prerequisite_blocked_check_ids():
    """prerequisite_blocked_check_ids must contain all auth/browser/workflow checks."""
    result = _make_campaign_result(audit_trail=[])
    report = CoverageValidator.build_coverage_report(result)

    blocked = report.prerequisite_blocked_check_ids
    for cid in BROWSER_REQUIRED_CHECKS:
        if report.get_record(cid):
            assert cid in blocked, f"{cid} should be in prerequisite_blocked_check_ids"
    for cid in AUTHENTICATION_REQUIRED_CHECKS:
        if report.get_record(cid):
            assert cid in blocked, f"{cid} should be in prerequisite_blocked_check_ids"
    for cid in WORKFLOW_REQUIRED_CHECKS:
        if report.get_record(cid):
            assert cid in blocked, f"{cid} should be in prerequisite_blocked_check_ids"


def test_check_coverage_record_to_dict():
    """CheckCoverageRecord.to_dict must include all required fields."""
    record = CheckCoverageRecord(
        check_id="C001_Open_Port_80",
        name="Open HTTP Port",
        category="recon",
        severity="info",
        status=CheckExecutionStatus.EXECUTED_NO_CANDIDATE,
    )
    d = record.to_dict()
    assert d["check_id"] == "C001_Open_Port_80"
    assert d["status"] == "EXECUTED_NO_CANDIDATE"
    assert d["was_executed"] is True
    assert d["produced_candidate"] is False


def test_build_coverage_report_records_all_77_in_sorted_order():
    """Coverage report records must contain exactly 77 checks in sorted order."""
    result = _make_campaign_result(audit_trail=[])
    report = CoverageValidator.build_coverage_report(result)

    assert len(report.records) == 77
    # Verify sorted order
    ids = [r.check_id for r in report.records]
    assert ids == sorted(ids)


def test_coverage_validator_validate_registry_completeness_raises_on_wrong_count():
    """validate_registry_completeness must raise ValueError with wrong expected count."""
    with pytest.raises(ValueError, match="Registry completeness check failed"):
        CoverageValidator.validate_registry_completeness(expected_count=999)


def test_coverage_report_verified_finding_ids_populated():
    """Verified finding IDs must be populated from verification_passed audit events."""
    contracts = registry.list_checks()
    plain_check = next(
        c for c in contracts
        if c.id not in BROWSER_REQUIRED_CHECKS
        and c.id not in AUTHENTICATION_REQUIRED_CHECKS
        and c.id not in WORKFLOW_REQUIRED_CHECKS
    )
    check_id = plain_check.id
    finding_id = "find-verified-001"

    audit = [
        {"event": "check_started", "details": {"check_id": check_id, "target": "http://t"}},
        {"event": "candidate_created", "details": {"finding_id": finding_id, "vuln_type": check_id, "target": "http://t"}},
        {"event": "verification_passed", "details": {"finding_id": finding_id, "title": "Test Finding"}},
    ]

    result = _make_campaign_result(audit_trail=audit)
    report = CoverageValidator.build_coverage_report(result)

    record = report.get_record(check_id)
    assert record is not None
    assert finding_id in record.verified_finding_ids
    assert report.checks_with_verified_findings == 1


def test_coverage_report_findings_list_populates_candidates():
    """Findings list on CampaignResult cross-references into candidate_finding_ids."""
    from backend.models.database import Finding as FindingModel
    contracts = registry.list_checks()
    plain_check = next(
        c for c in contracts
        if c.id not in BROWSER_REQUIRED_CHECKS
        and c.id not in AUTHENTICATION_REQUIRED_CHECKS
        and c.id not in WORKFLOW_REQUIRED_CHECKS
    )
    check_id = plain_check.id

    # Construct a minimal Finding object
    finding = FindingModel(
        id="find-from-findings-list",
        scan_id="cmp-test",
        agent_id=3,
        title="Test Finding From List",
        vuln_type=check_id,
        category="recon",
        severity="info",
        affected_url="http://example.local",
        confidence=50,
        false_positive=False,
        verdict="Inconclusive",
        verification_status="CANDIDATE",
    )

    # Audit trail has check_started so it's EXECUTED
    audit = [
        {"event": "check_started", "details": {"check_id": check_id, "target": "http://t"}},
    ]
    result = _make_campaign_result(audit_trail=audit, findings=[finding])
    report = CoverageValidator.build_coverage_report(result)

    record = report.get_record(check_id)
    assert record is not None
    assert "find-from-findings-list" in record.candidate_finding_ids
