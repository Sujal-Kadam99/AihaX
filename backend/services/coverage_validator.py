"""AihaX Phase 6 — 77-Check Coverage Validator & Campaign Coverage Report.

Provides:
- CoverageValidator: Maps each C001–C077 check to its execution status
  and generates a machine-readable coverage matrix.
- CampaignCoverageReport: Structured per-check execution evidence record
  derived from a completed CampaignResult.
- Coverage assertions that verify ≥N checks were reached in an execution.

Design guarantees:
- Zero hallucination: coverage matrix is derived solely from registry + audit trail
- Deterministic: same input always produces same coverage report
- Non-destructive: read-only analysis of completed campaign results
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

import backend.agents.checks  # Ensure all 77 checks are registered
from backend.core.check_registry import CheckCategory, CheckContract, Severity, registry
from backend.services.campaign_executor import (
    AUTHENTICATION_REQUIRED_CHECKS,
    BROWSER_REQUIRED_CHECKS,
    WORKFLOW_REQUIRED_CHECKS,
    CampaignResult,
)

logger = logging.getLogger("backend.services.coverage_validator")


# ──────────────────────────────────────────────────────────────────────────────
# 1. CHECK EXECUTION STATUS ENUM
# ──────────────────────────────────────────────────────────────────────────────

class CheckExecutionStatus(str, Enum):
    """Per-check execution status in a completed campaign."""
    EXECUTED_CANDIDATE        = "EXECUTED_CANDIDATE"        # Check ran → produced candidate finding
    EXECUTED_NO_CANDIDATE     = "EXECUTED_NO_CANDIDATE"     # Check ran → no candidate (clean)
    SKIPPED_PREREQUISITE      = "SKIPPED_PREREQUISITE"      # Skipped — missing browser/auth/workflow
    SKIPPED_BUDGET            = "SKIPPED_BUDGET"            # Skipped — request budget exhausted
    SKIPPED_SCOPE             = "SKIPPED_SCOPE"             # Skipped — target out-of-scope
    SKIPPED_NOT_SELECTED      = "SKIPPED_NOT_SELECTED"      # Skipped — not in selected_checks filter
    PLANNED_UNREACHED         = "PLANNED_UNREACHED"         # In plan but execution never reached it
    NOT_REGISTERED            = "NOT_REGISTERED"            # Check not present in registry (impossible)


# ──────────────────────────────────────────────────────────────────────────────
# 2. PER-CHECK COVERAGE RECORD
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class CheckCoverageRecord:
    """Coverage record for a single check in a campaign."""
    check_id: str
    name: str
    category: str
    severity: str
    status: CheckExecutionStatus
    prerequisite_gap: Optional[str] = None      # Why the check was skipped (if applicable)
    candidate_finding_ids: List[str] = field(default_factory=list)
    verified_finding_ids: List[str] = field(default_factory=list)
    audit_events: List[str] = field(default_factory=list)
    requires_auth: bool = False
    requires_browser: bool = False
    requires_workflow: bool = False
    target_surface: str = "web"

    @property
    def was_executed(self) -> bool:
        return self.status in (
            CheckExecutionStatus.EXECUTED_CANDIDATE,
            CheckExecutionStatus.EXECUTED_NO_CANDIDATE,
        )

    @property
    def produced_candidate(self) -> bool:
        return self.status == CheckExecutionStatus.EXECUTED_CANDIDATE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "status": self.status.value,
            "was_executed": self.was_executed,
            "produced_candidate": self.produced_candidate,
            "prerequisite_gap": self.prerequisite_gap,
            "candidate_finding_ids": self.candidate_finding_ids,
            "verified_finding_ids": self.verified_finding_ids,
            "audit_events": self.audit_events,
            "requires_auth": self.requires_auth,
            "requires_browser": self.requires_browser,
            "requires_workflow": self.requires_workflow,
            "target_surface": self.target_surface,
        }


# ──────────────────────────────────────────────────────────────────────────────
# 3. CAMPAIGN COVERAGE REPORT
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class CampaignCoverageReport:
    """Machine-readable coverage matrix for a completed campaign."""
    campaign_id: str
    target_url: str
    total_registered_checks: int
    checks_executed: int
    checks_with_candidates: int
    checks_with_verified_findings: int
    checks_skipped_prerequisite: int
    checks_skipped_budget: int
    checks_skipped_scope: int
    checks_planned_unreached: int
    coverage_percentage: float          # % of registered checks that were executed
    reachable_percentage: float         # % of registered checks reachable without prerequisites
    records: List[CheckCoverageRecord] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    mode: str = "SAFE_SCAN"

    @property
    def executed_check_ids(self) -> Set[str]:
        return {r.check_id for r in self.records if r.was_executed}

    @property
    def candidate_check_ids(self) -> Set[str]:
        return {r.check_id for r in self.records if r.produced_candidate}

    @property
    def prerequisite_blocked_check_ids(self) -> Set[str]:
        return {r.check_id for r in self.records if r.status == CheckExecutionStatus.SKIPPED_PREREQUISITE}

    def get_record(self, check_id: str) -> Optional[CheckCoverageRecord]:
        for r in self.records:
            if r.check_id == check_id:
                return r
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "target_url": self.target_url,
            "mode": self.mode,
            "generated_at": self.generated_at,
            "summary": {
                "total_registered_checks": self.total_registered_checks,
                "checks_executed": self.checks_executed,
                "checks_with_candidates": self.checks_with_candidates,
                "checks_with_verified_findings": self.checks_with_verified_findings,
                "checks_skipped_prerequisite": self.checks_skipped_prerequisite,
                "checks_skipped_budget": self.checks_skipped_budget,
                "checks_skipped_scope": self.checks_skipped_scope,
                "checks_planned_unreached": self.checks_planned_unreached,
                "coverage_percentage": round(self.coverage_percentage, 2),
                "reachable_percentage": round(self.reachable_percentage, 2),
            },
            "records": [r.to_dict() for r in self.records],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def assert_minimum_coverage(
        self,
        min_executed: int = 50,
        min_reachable_pct: float = 60.0,
    ) -> None:
        """Assert minimum coverage thresholds. Raises AssertionError with details if not met."""
        if self.checks_executed < min_executed:
            raise AssertionError(
                f"Coverage assertion failed: only {self.checks_executed} checks executed "
                f"(minimum required: {min_executed}). "
                f"Skipped-prerequisite: {self.checks_skipped_prerequisite}, "
                f"Skipped-budget: {self.checks_skipped_budget}."
            )
        if self.reachable_percentage < min_reachable_pct:
            raise AssertionError(
                f"Reachable coverage {self.reachable_percentage:.1f}% < {min_reachable_pct}% minimum. "
                f"Total registered: {self.total_registered_checks}, "
                f"Executed: {self.checks_executed}."
            )


# ──────────────────────────────────────────────────────────────────────────────
# 4. COVERAGE VALIDATOR
# ──────────────────────────────────────────────────────────────────────────────

class CoverageValidator:
    """Derives a machine-readable 77-check coverage matrix from a CampaignResult.

    Usage::

        from backend.services.coverage_validator import CoverageValidator

        report = CoverageValidator.build_coverage_report(campaign_result)
        report.assert_minimum_coverage(min_executed=50)
        print(report.to_json())
    """

    @classmethod
    def build_coverage_report(
        cls,
        campaign_result: CampaignResult,
        expected_total: int = 77,
    ) -> CampaignCoverageReport:
        """Build a CampaignCoverageReport from a completed CampaignResult.

        Args:
            campaign_result: A completed CampaignResult from CampaignExecutor.execute_campaign().
            expected_total: Expected number of registered checks (default 77).

        Returns:
            CampaignCoverageReport with per-check execution status.
        """
        all_contracts: List[CheckContract] = registry.list_checks()
        audit_trail = campaign_result.audit_trail or []

        # ── Derive per-check execution status from audit trail ─────────────────
        started_checks: Set[str] = set()
        errored_checks: Set[str] = set()
        halted_budget_checks: Set[str] = set()
        candidate_check_map: Dict[str, List[str]] = {}    # check_id → [finding_ids]
        verified_check_map: Dict[str, List[str]] = {}     # check_id → [finding_ids]
        check_audit_events: Dict[str, List[str]] = {}     # check_id → [event names]

        for event in audit_trail:
            evt_name = event.get("event", "")
            details = event.get("details", {})

            check_id = details.get("check_id")
            finding_id = details.get("finding_id")
            vuln_type = details.get("vuln_type")  # vuln_type = check_id in CampaignExecutor

            if evt_name == "check_started" and check_id:
                started_checks.add(check_id)
                check_audit_events.setdefault(check_id, []).append("check_started")

            elif evt_name == "check_error" and check_id:
                errored_checks.add(check_id)
                check_audit_events.setdefault(check_id, []).append("check_error")

            elif evt_name == "check_halted_budget":
                # Details contain: reason, target — we don't have check_id here
                # But if check_id is present use it
                if check_id:
                    halted_budget_checks.add(check_id)
                    check_audit_events.setdefault(check_id, []).append("check_halted_budget")

            elif evt_name == "candidate_created" and finding_id:
                # Map finding → check via vuln_type (= check_id in _create_candidate_finding)
                if vuln_type:
                    candidate_check_map.setdefault(vuln_type, []).append(finding_id)
                    check_audit_events.setdefault(vuln_type, []).append("candidate_created")

            elif evt_name == "verification_passed" and finding_id:
                # We need to map finding_id back to check_id
                # Use candidate_check_map to find which check produced this finding
                for cid, fids in candidate_check_map.items():
                    if finding_id in fids:
                        verified_check_map.setdefault(cid, []).append(finding_id)
                        check_audit_events.setdefault(cid, []).append("verification_passed")
                        break

        # Also derive from findings list (cross-reference for completeness)
        for finding in campaign_result.findings or []:
            cid = getattr(finding, "vuln_type", None)
            fid = getattr(finding, "id", None)
            verdict = getattr(finding, "verdict", "")
            if cid and fid:
                if fid not in candidate_check_map.get(cid, []):
                    candidate_check_map.setdefault(cid, []).append(fid)
                if verdict == "Verified" and fid not in verified_check_map.get(cid, []):
                    verified_check_map.setdefault(cid, []).append(fid)

        # ── Build per-check records ─────────────────────────────────────────────
        records: List[CheckCoverageRecord] = []
        req_browser = BROWSER_REQUIRED_CHECKS
        req_auth = AUTHENTICATION_REQUIRED_CHECKS
        req_workflow = WORKFLOW_REQUIRED_CHECKS

        for contract in sorted(all_contracts, key=lambda c: c.id):
            cid = contract.id

            needs_browser = cid in req_browser
            needs_auth = cid in req_auth
            needs_workflow = cid in req_workflow

            # Determine status
            if cid in started_checks:
                if cid in candidate_check_map:
                    status = CheckExecutionStatus.EXECUTED_CANDIDATE
                else:
                    status = CheckExecutionStatus.EXECUTED_NO_CANDIDATE
                prereq_gap = None

            elif cid in halted_budget_checks:
                status = CheckExecutionStatus.SKIPPED_BUDGET
                prereq_gap = "Request budget exhausted before check execution"

            elif needs_browser:
                status = CheckExecutionStatus.SKIPPED_PREREQUISITE
                prereq_gap = "Browser capability unavailable (headless browser not provided)"

            elif needs_auth:
                status = CheckExecutionStatus.SKIPPED_PREREQUISITE
                prereq_gap = "Authentication context not provided"

            elif needs_workflow:
                status = CheckExecutionStatus.SKIPPED_PREREQUISITE
                prereq_gap = "Workflow state capability not provided"

            else:
                # Was planned but execution never reached it (budget or concurrency limit)
                status = CheckExecutionStatus.PLANNED_UNREACHED
                prereq_gap = "Check was eligible but not reached during execution (budget/concurrency)"

            record = CheckCoverageRecord(
                check_id=cid,
                name=contract.name,
                category=contract.category.value,
                severity=contract.severity.value,
                status=status,
                prerequisite_gap=prereq_gap,
                candidate_finding_ids=list(candidate_check_map.get(cid, [])),
                verified_finding_ids=list(verified_check_map.get(cid, [])),
                audit_events=list(check_audit_events.get(cid, [])),
                requires_auth=needs_auth,
                requires_browser=needs_browser,
                requires_workflow=needs_workflow,
                target_surface=contract.target_surface,
            )
            records.append(record)

        # ── Aggregate counters ─────────────────────────────────────────────────
        n_executed = sum(1 for r in records if r.was_executed)
        n_candidates = sum(1 for r in records if r.produced_candidate)
        n_verified = sum(
            1 for r in records if r.verified_finding_ids
        )
        n_prereq = sum(
            1 for r in records if r.status == CheckExecutionStatus.SKIPPED_PREREQUISITE
        )
        n_budget = sum(
            1 for r in records if r.status == CheckExecutionStatus.SKIPPED_BUDGET
        )
        n_scope = sum(
            1 for r in records if r.status == CheckExecutionStatus.SKIPPED_SCOPE
        )
        n_unreached = sum(
            1 for r in records if r.status == CheckExecutionStatus.PLANNED_UNREACHED
        )

        total = len(records)
        coverage_pct = (n_executed / total * 100) if total > 0 else 0.0

        # Reachable = checks that don't require browser/auth/workflow
        n_reachable_pool = sum(
            1 for r in records
            if not r.requires_browser and not r.requires_auth and not r.requires_workflow
        )
        n_reachable_executed = sum(
            1 for r in records
            if r.was_executed
        )
        reachable_pct = (n_reachable_executed / n_reachable_pool * 100) if n_reachable_pool > 0 else 0.0

        return CampaignCoverageReport(
            campaign_id=campaign_result.campaign_id,
            target_url=campaign_result.target_url,
            total_registered_checks=total,
            checks_executed=n_executed,
            checks_with_candidates=n_candidates,
            checks_with_verified_findings=n_verified,
            checks_skipped_prerequisite=n_prereq,
            checks_skipped_budget=n_budget,
            checks_skipped_scope=n_scope,
            checks_planned_unreached=n_unreached,
            coverage_percentage=coverage_pct,
            reachable_percentage=reachable_pct,
            records=records,
            mode=campaign_result.mode,
        )

    @classmethod
    def build_registry_matrix(cls) -> Dict[str, Any]:
        """Build a static check registry matrix (no campaign needed).

        Returns a structured dict of all 77 checks grouped by category,
        with their prerequisite requirements and target surfaces.
        Useful for pre-campaign planning and audit.
        """
        all_contracts: List[CheckContract] = registry.list_checks()

        by_category: Dict[str, List[Dict[str, Any]]] = {}
        for contract in sorted(all_contracts, key=lambda c: c.id):
            cat = contract.category.value
            if cat not in by_category:
                by_category[cat] = []

            cid = contract.id
            by_category[cat].append({
                "check_id": cid,
                "name": contract.name,
                "severity": contract.severity.value,
                "requires_auth": cid in AUTHENTICATION_REQUIRED_CHECKS,
                "requires_browser": cid in BROWSER_REQUIRED_CHECKS,
                "requires_workflow": cid in WORKFLOW_REQUIRED_CHECKS,
                "requires_parameters": contract.requires_parameters,
                "target_surface": contract.target_surface,
                "max_requests": contract.max_requests,
                "required_capabilities": sorted(contract.required_capabilities),
                "cwe": contract.cwe,
                "owasp_category": contract.owasp_category,
            })

        total = len(all_contracts)
        total_http_only = sum(
            1 for c in all_contracts
            if c.id not in BROWSER_REQUIRED_CHECKS
            and c.id not in AUTHENTICATION_REQUIRED_CHECKS
            and c.id not in WORKFLOW_REQUIRED_CHECKS
        )

        return {
            "total_registered": total,
            "http_only_executable": total_http_only,
            "browser_required": len(BROWSER_REQUIRED_CHECKS),
            "auth_required": len(AUTHENTICATION_REQUIRED_CHECKS),
            "workflow_required": len(WORKFLOW_REQUIRED_CHECKS),
            "by_category": by_category,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    @classmethod
    def validate_registry_completeness(cls, expected_count: int = 77) -> Dict[str, Any]:
        """Validate that all expected checks are correctly registered.

        Returns a dict with validation results. Raises ValueError if checks are missing.
        """
        all_contracts = registry.list_checks()
        actual_count = len(all_contracts)

        ids = [c.id for c in all_contracts]
        duplicates = [cid for cid in ids if ids.count(cid) > 1]
        missing_cwe = [c.id for c in all_contracts if not c.cwe]
        invalid_contracts = []

        for c in all_contracts:
            try:
                c.validate_contract()
            except Exception as e:
                invalid_contracts.append({"check_id": c.id, "error": str(e)})

        result = {
            "expected_count": expected_count,
            "actual_count": actual_count,
            "count_matches": actual_count == expected_count,
            "duplicate_ids": duplicates,
            "checks_missing_cwe": missing_cwe,
            "invalid_contracts": invalid_contracts,
            "all_valid": (
                actual_count == expected_count
                and not duplicates
                and not invalid_contracts
            ),
        }

        if not result["count_matches"]:
            raise ValueError(
                f"Registry completeness check failed: expected {expected_count} checks, "
                f"found {actual_count}. Missing or extra registrations detected."
            )
        if duplicates:
            raise ValueError(f"Duplicate check IDs detected: {duplicates}")
        if invalid_contracts:
            raise ValueError(f"Invalid check contracts: {invalid_contracts}")

        return result


# ──────────────────────────────────────────────────────────────────────────────
# 5. CONVENIENCE EXPORTS
# ──────────────────────────────────────────────────────────────────────────────

__all__ = [
    "CheckExecutionStatus",
    "CheckCoverageRecord",
    "CampaignCoverageReport",
    "CoverageValidator",
]
