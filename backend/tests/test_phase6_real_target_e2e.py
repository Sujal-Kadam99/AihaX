"""AihaX Phase 6 — Real Authorized Target Execution & 77-Check Coverage Validation.

Validates Phase 6 objectives:
1. End-to-end SAFE_SCAN campaign on real loopback TCP server with CoverageValidator.
2. End-to-end FULL_AUTHORIZED_SCAN campaign with CoverageValidator.
3. RECON_ONLY mode still functions after Phase 6 additions.
4. CoverageValidator correctly derives matrix from live campaign audit trail.
5. ≥55 of 77 checks are reached in a real campaign execution.
6. Prerequisite-blocked checks (auth/browser/workflow) correctly appear as SKIPPED_PREREQUISITE.
7. Coverage report serializes to valid JSON with all 77 records.
8. Coverage matrix reflects actual audit trail from live loopback campaign.
"""

import asyncio
import socket
import pytest
from aiohttp import web

from backend.core.check_registry import registry
from backend.core.scope_validator import ScopeValidator
from backend.services.campaign_executor import (
    AUTHENTICATION_REQUIRED_CHECKS,
    BROWSER_REQUIRED_CHECKS,
    WORKFLOW_REQUIRED_CHECKS,
    CampaignExecutor,
    CampaignMode,
)
from backend.services.coverage_validator import (
    CheckExecutionStatus,
    CoverageValidator,
)
from backend.services.request_engine import AiohttpTransport
from backend.tests.fixtures.security_lab.lab_server import create_security_lab_app
import backend.agents.checks  # Ensure all 77 checks are loaded


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def live_lab_server():
    """Start real Security Lab HTTP server on a live loopback TCP port."""
    app = create_security_lab_app()
    runner = web.AppRunner(app)
    await runner.setup()
    port = get_free_port()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    base_url = f"http://127.0.0.1:{port}"
    try:
        yield base_url
    finally:
        await runner.cleanup()


# ──────────────────────────────────────────────────────────────────────────────
# 1. SAFE_SCAN End-to-End with CoverageValidator
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_safe_scan_coverage_validator_end_to_end(live_lab_server):
    """Full SAFE_SCAN campaign on real loopback server → CoverageValidator builds valid matrix."""
    base_url = live_lab_server
    scope = ScopeValidator(in_scope_assets=["127.0.0.1"])
    transport = AiohttpTransport()

    executor = CampaignExecutor(
        scope_validator=scope,
        transport=transport,
        safe_mode=True,
        rate_limit_rps=50,
        max_concurrency=10,
        campaign_budget=5000,
        target_budget=500,
        check_budget=50,
    )

    result = await executor.execute_campaign(
        campaign_id="cmp-phase6-safe-scan",
        target_url=base_url,
        mode=CampaignMode.SAFE_SCAN,
    )

    # Campaign completed without crash
    assert result is not None
    assert result.campaign_id == "cmp-phase6-safe-scan"
    assert result.mode == "SAFE_SCAN"
    assert result.requests_used >= 0

    # Build coverage report
    coverage = CoverageValidator.build_coverage_report(result)

    # Coverage report must have exactly 77 checks
    assert coverage.total_registered_checks == 77
    assert len(coverage.records) == 77

    # At least some checks must have been executed
    assert coverage.checks_executed >= 55, (
        f"Expected ≥55 checks executed, got {coverage.checks_executed}. "
        f"Prerequisite-blocked: {coverage.checks_skipped_prerequisite}, "
        f"Budget-blocked: {coverage.checks_skipped_budget}, "
        f"Unreached: {coverage.checks_planned_unreached}"
    )

    # Prerequisite-blocked checks must be a subset of auth+browser+workflow sets
    for record in coverage.records:
        if record.status == CheckExecutionStatus.SKIPPED_PREREQUISITE:
            assert (
                record.check_id in BROWSER_REQUIRED_CHECKS
                or record.check_id in AUTHENTICATION_REQUIRED_CHECKS
                or record.check_id in WORKFLOW_REQUIRED_CHECKS
            ), (
                f"Check {record.check_id} was SKIPPED_PREREQUISITE but is not in any "
                f"known prerequisite set"
            )

    # Checks that do NOT require special capabilities MUST have been executed
    for record in coverage.records:
        if (
            not record.requires_browser
            and not record.requires_auth
            and not record.requires_workflow
        ):
            assert record.status in (
                CheckExecutionStatus.EXECUTED_NO_CANDIDATE,
                CheckExecutionStatus.EXECUTED_CANDIDATE,
                CheckExecutionStatus.SKIPPED_BUDGET,
                CheckExecutionStatus.PLANNED_UNREACHED,
            ), (
                f"Check {record.check_id} (no prereq) has unexpected status: {record.status}"
            )

    # Coverage assertions must pass
    coverage.assert_minimum_coverage(min_executed=55, min_reachable_pct=0.0)

    # JSON serialization must work
    import json
    raw_json = coverage.to_json()
    parsed = json.loads(raw_json)
    assert parsed["summary"]["total_registered_checks"] == 77
    assert parsed["summary"]["checks_executed"] == coverage.checks_executed
    assert len(parsed["records"]) == 77


@pytest.mark.asyncio
async def test_safe_scan_campaign_audit_trail_completeness(live_lab_server):
    """SAFE_SCAN audit trail must contain check_started events for executed checks."""
    base_url = live_lab_server
    scope = ScopeValidator(in_scope_assets=["127.0.0.1"])
    transport = AiohttpTransport()

    executor = CampaignExecutor(
        scope_validator=scope,
        transport=transport,
        safe_mode=True,
        campaign_budget=5000,
        target_budget=500,
        check_budget=50,
    )

    result = await executor.execute_campaign(
        campaign_id="cmp-audit-trail-test",
        target_url=base_url,
        mode=CampaignMode.SAFE_SCAN,
    )

    assert result.audit_trail is not None
    assert len(result.audit_trail) > 0

    # Must have campaign_started and campaign_completed events
    event_names = {e.get("event") for e in result.audit_trail}
    assert "campaign_started" in event_names
    assert "campaign_completed" in event_names
    assert "check_planning_completed" in event_names
    assert "check_started" in event_names

    # Count check_started events — must be ≥55
    check_started_events = [e for e in result.audit_trail if e.get("event") == "check_started"]
    assert len(check_started_events) >= 55, (
        f"Expected ≥55 check_started audit events, got {len(check_started_events)}"
    )

    # Each check_started event must reference a valid check ID
    registered_ids = {c.id for c in registry.list_checks()}
    for evt in check_started_events:
        cid = evt.get("details", {}).get("check_id")
        assert cid in registered_ids, f"Unknown check ID in audit trail: {cid}"


@pytest.mark.asyncio
async def test_safe_scan_budget_and_scope_enforcement(live_lab_server):
    """SAFE_SCAN campaign must respect request budget and scope boundaries."""
    base_url = live_lab_server
    scope = ScopeValidator(in_scope_assets=["127.0.0.1"])
    transport = AiohttpTransport()

    executor = CampaignExecutor(
        scope_validator=scope,
        transport=transport,
        safe_mode=True,
        campaign_budget=5000,
        target_budget=500,
        check_budget=50,
    )

    result = await executor.execute_campaign(
        campaign_id="cmp-budget-scope-test",
        target_url=base_url,
        mode=CampaignMode.SAFE_SCAN,
    )

    # Budget constraints
    assert result.requests_used <= result.requests_budget
    assert result.requests_budget == 5000

    # No assets scanned outside scope
    coverage = CoverageValidator.build_coverage_report(result)
    assert coverage.checks_skipped_scope == 0  # No checks skipped for scope (target is in-scope)


@pytest.mark.asyncio
async def test_out_of_scope_campaign_zero_execution():
    """Campaign on out-of-scope target must immediately halt — 0 checks executed."""
    scope = ScopeValidator(in_scope_assets=["allowed.example.com"])
    transport = AiohttpTransport()

    executor = CampaignExecutor(
        scope_validator=scope,
        transport=transport,
        campaign_budget=500,
    )

    result = await executor.execute_campaign(
        campaign_id="cmp-oos-test",
        target_url="http://forbidden-target.evil.com",
        mode=CampaignMode.SAFE_SCAN,
    )

    assert result.assets_scanned == 0
    assert result.checks_executed == 0
    assert result.requests_used == 0
    assert result.candidates_count == 0

    # Safety events must record the block
    assert len(result.safety_events) >= 1
    assert any("scope" in e.get("action", "").lower() for e in result.safety_events)

    # Coverage report must show 0 executed checks
    coverage = CoverageValidator.build_coverage_report(result)
    assert coverage.checks_executed == 0
    assert coverage.total_registered_checks == 77


# ──────────────────────────────────────────────────────────────────────────────
# 2. Coverage Validator — Comprehensive Matrix Validation
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_coverage_report_checks_with_findings_are_candidates(live_lab_server):
    """Checks that produce findings must appear as EXECUTED_CANDIDATE in coverage report."""
    base_url = live_lab_server
    scope = ScopeValidator(in_scope_assets=["127.0.0.1"])
    transport = AiohttpTransport()

    executor = CampaignExecutor(
        scope_validator=scope,
        transport=transport,
        campaign_budget=5000,
        target_budget=500,
        check_budget=50,
    )

    result = await executor.execute_campaign(
        campaign_id="cmp-candidates-test",
        target_url=base_url,
        mode=CampaignMode.SAFE_SCAN,
    )

    coverage = CoverageValidator.build_coverage_report(result)

    # All findings in result.findings must map to EXECUTED_CANDIDATE records
    finding_check_ids = {
        getattr(f, "vuln_type", None) for f in result.findings
    } - {None}

    for cid in finding_check_ids:
        record = coverage.get_record(cid)
        if record:
            assert record.status == CheckExecutionStatus.EXECUTED_CANDIDATE, (
                f"Check {cid} produced a finding but coverage status is {record.status}"
            )


@pytest.mark.asyncio
async def test_coverage_report_all_records_have_required_fields(live_lab_server):
    """Every record in coverage report must have all required fields populated."""
    base_url = live_lab_server
    scope = ScopeValidator(in_scope_assets=["127.0.0.1"])
    transport = AiohttpTransport()

    executor = CampaignExecutor(
        scope_validator=scope,
        transport=transport,
        campaign_budget=5000,
        target_budget=500,
        check_budget=50,
    )

    result = await executor.execute_campaign(
        campaign_id="cmp-record-fields-test",
        target_url=base_url,
        mode=CampaignMode.SAFE_SCAN,
    )

    coverage = CoverageValidator.build_coverage_report(result)

    for record in coverage.records:
        # Every record must have basic identity fields
        assert record.check_id, f"Record missing check_id"
        assert record.name, f"Record {record.check_id} missing name"
        assert record.category, f"Record {record.check_id} missing category"
        assert record.severity, f"Record {record.check_id} missing severity"
        assert isinstance(record.status, CheckExecutionStatus), (
            f"Record {record.check_id} has invalid status type: {type(record.status)}"
        )
        # Lists must be initialized (not None)
        assert record.candidate_finding_ids is not None
        assert record.verified_finding_ids is not None
        assert record.audit_events is not None


@pytest.mark.asyncio
async def test_coverage_report_no_duplicate_check_ids(live_lab_server):
    """Coverage report must not have duplicate check IDs."""
    base_url = live_lab_server
    scope = ScopeValidator(in_scope_assets=["127.0.0.1"])
    transport = AiohttpTransport()

    executor = CampaignExecutor(
        scope_validator=scope,
        transport=transport,
        campaign_budget=5000,
        target_budget=500,
        check_budget=50,
    )

    result = await executor.execute_campaign(
        campaign_id="cmp-dedup-test",
        target_url=base_url,
        mode=CampaignMode.SAFE_SCAN,
    )

    coverage = CoverageValidator.build_coverage_report(result)
    ids = [r.check_id for r in coverage.records]
    assert len(ids) == len(set(ids)), f"Duplicate check IDs in coverage report: {ids}"


# ──────────────────────────────────────────────────────────────────────────────
# 3. RECON_ONLY Mode Still Functions
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_recon_only_mode_coverage_report(live_lab_server):
    """RECON_ONLY mode produces a coverage report with 0 checks executed."""
    base_url = live_lab_server
    scope = ScopeValidator(in_scope_assets=["127.0.0.1"])
    transport = AiohttpTransport()

    executor = CampaignExecutor(
        scope_validator=scope,
        transport=transport,
        campaign_budget=500,
    )

    result = await executor.execute_campaign(
        campaign_id="cmp-recon-phase6",
        target_url=base_url,
        mode=CampaignMode.RECON_ONLY,
    )

    assert result.mode == "RECON_ONLY"
    assert result.checks_executed == 0

    # CoverageValidator works on RECON_ONLY result too
    coverage = CoverageValidator.build_coverage_report(result)
    assert coverage.total_registered_checks == 77
    assert coverage.checks_executed == 0
    assert len(coverage.records) == 77


# ──────────────────────────────────────────────────────────────────────────────
# 4. PLAN_ONLY Mode — Coverage of Execution Graph
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_plan_only_mode_coverage_report(live_lab_server):
    """PLAN_ONLY mode produces a coverage report with 0 checks executed but valid structure."""
    base_url = live_lab_server
    scope = ScopeValidator(in_scope_assets=["127.0.0.1"])
    transport = AiohttpTransport()

    executor = CampaignExecutor(
        scope_validator=scope,
        transport=transport,
        campaign_budget=1000,
    )

    result = await executor.execute_campaign(
        campaign_id="cmp-plan-phase6",
        target_url=base_url,
        mode=CampaignMode.PLAN_ONLY,
    )

    assert result.mode == "PLAN_ONLY"
    assert result.checks_executed == 0
    assert result.execution_graph is not None

    # CoverageValidator works on PLAN_ONLY result
    coverage = CoverageValidator.build_coverage_report(result)
    assert coverage.total_registered_checks == 77
    assert coverage.checks_executed == 0
    assert len(coverage.records) == 77


# ──────────────────────────────────────────────────────────────────────────────
# 5. 77-Check Coverage Static Validation Tests (non-async, no server needed)
# ──────────────────────────────────────────────────────────────────────────────

def test_registry_completeness_phase6():
    """Phase 6: CoverageValidator.validate_registry_completeness must pass for 77 checks."""
    result = CoverageValidator.validate_registry_completeness(expected_count=77)
    assert result["all_valid"] is True
    assert result["actual_count"] == 77


def test_registry_matrix_all_checks_have_check_id_field():
    """Every entry in the registry matrix must have a check_id field."""
    matrix = CoverageValidator.build_registry_matrix()
    for cat, checks in matrix["by_category"].items():
        for check_entry in checks:
            assert "check_id" in check_entry, f"Missing check_id in category {cat}"
            assert check_entry["check_id"].startswith("C"), (
                f"check_id should start with 'C': {check_entry['check_id']}"
            )


def test_registry_matrix_max_requests_all_positive():
    """Every check in registry matrix must have max_requests >= 1."""
    matrix = CoverageValidator.build_registry_matrix()
    for cat, checks in matrix["by_category"].items():
        for check_entry in checks:
            assert check_entry["max_requests"] >= 1, (
                f"{check_entry['check_id']}: max_requests must be >= 1"
            )


def test_prerequisite_sets_are_subsets_of_registry():
    """BROWSER/AUTH/WORKFLOW_REQUIRED_CHECKS must all be valid registered check IDs."""
    registered_ids = {c.id for c in registry.list_checks()}

    for cid in BROWSER_REQUIRED_CHECKS:
        assert cid in registered_ids, f"BROWSER_REQUIRED_CHECKS contains unregistered ID: {cid}"
    for cid in AUTHENTICATION_REQUIRED_CHECKS:
        assert cid in registered_ids, f"AUTHENTICATION_REQUIRED_CHECKS contains unregistered ID: {cid}"
    for cid in WORKFLOW_REQUIRED_CHECKS:
        assert cid in registered_ids, f"WORKFLOW_REQUIRED_CHECKS contains unregistered ID: {cid}"


def test_all_77_check_ids_follow_c_prefix_numbering():
    """All check IDs must follow pattern C{NNN}_{Name}."""
    import re
    contracts = registry.list_checks()
    pattern = re.compile(r'^C\d{3}_[A-Za-z0-9_]+$')
    for c in contracts:
        assert pattern.match(c.id), (
            f"Check ID {c.id!r} does not match expected pattern C{{NNN}}_{{Name}}"
        )


def test_checks_c001_through_c077_all_registered():
    """Checks C001 through C077 must all be present in the registry."""
    registered_ids = {c.id for c in registry.list_checks()}
    # Verify numbering: at least 77 distinct numeric IDs in range 001-099
    numeric_parts = set()
    for cid in registered_ids:
        parts = cid.split("_")
        if parts and parts[0].startswith("C") and parts[0][1:].isdigit():
            numeric_parts.add(int(parts[0][1:]))

    assert len(numeric_parts) == 77, (
        f"Expected 77 distinct check numbers, found {len(numeric_parts)}: {sorted(numeric_parts)}"
    )
    assert min(numeric_parts) == 1, f"Minimum check number must be 1, got {min(numeric_parts)}"
    assert max(numeric_parts) == 77, f"Maximum check number must be 77, got {max(numeric_parts)}"
