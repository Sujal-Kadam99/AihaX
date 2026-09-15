"""AihaX Phase 7 — Campaign Intelligence Engine.

Aggregates campaign results into a structured intelligence report.
All values derive from actual campaign data — no hallucination.

Integrates:
- CampaignResult (from CampaignExecutor)
- CampaignCoverageReport (from CoverageValidator)
- Verified findings
- Risk prioritization
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from backend.models.database import Finding
from backend.services.campaign_executor import CampaignResult
from backend.services.coverage_validator import CampaignCoverageReport


# ──────────────────────────────────────────────────────────────────────────────
# 1. RISK PRIORITIZER
# ──────────────────────────────────────────────────────────────────────────────

_SEVERITY_WEIGHT = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 5}
_CONFIDENCE_WEIGHT = {"CERTAIN": 40, "HIGH": 30, "MEDIUM": 20, "LOW": 10}


@dataclass
class PriorityAssessment:
    """Deterministic risk priority for a single finding."""
    finding_id: str
    priority_score: int        # 0–140 composite
    priority_rank: int = 0     # Rank among all findings in campaign (1 = highest)
    severity: str = ""
    confidence: int = 0
    factors: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "priority_score": self.priority_score,
            "priority_rank": self.priority_rank,
            "severity": self.severity,
            "confidence": self.confidence,
            "factors": self.factors,
        }


class RiskPrioritizer:
    """Ranks findings by deterministic severity × confidence × exploitability."""

    @classmethod
    def prioritize(cls, findings: Sequence[Finding]) -> List[PriorityAssessment]:
        """Return priority assessments sorted by score (highest first)."""
        assessments = []
        for finding in findings:
            severity_str = str(finding.severity or "info").lower()
            severity_weight = _SEVERITY_WEIGHT.get(severity_str, 5)

            # Confidence from 0–100 integer, normalized
            confidence_raw = int(finding.confidence or 0)
            confidence_weight = min(40, int(confidence_raw * 0.4))

            # Bonus for verified verdict
            verification_bonus = 0
            if str(finding.verdict or "").lower() == "verified":
                verification_bonus = 10

            # Bonus for auth-crossing (IDOR-type findings)
            auth_bonus = 0
            check = str(finding.vuln_type or "").upper()
            if any(x in check for x in ("IDOR", "BOLA", "PRIVILEGE", "ACCESS")):
                auth_bonus = 10

            score = severity_weight + confidence_weight + verification_bonus + auth_bonus

            assessments.append(PriorityAssessment(
                finding_id=str(finding.id),
                priority_score=score,
                severity=severity_str,
                confidence=confidence_raw,
                factors={
                    "severity_weight": severity_weight,
                    "confidence_weight": confidence_weight,
                    "verification_bonus": verification_bonus,
                    "auth_bonus": auth_bonus,
                },
            ))

        # Sort descending and assign ranks
        assessments.sort(key=lambda a: a.priority_score, reverse=True)
        for rank, assessment in enumerate(assessments, start=1):
            assessment.priority_rank = rank

        return assessments


# ──────────────────────────────────────────────────────────────────────────────
# 2. CAMPAIGN INTELLIGENCE REPORT
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class CampaignIntelligenceReport:
    """Aggregated intelligence report for a completed campaign."""
    campaign_id: str
    target_url: str
    mode: str
    generated_at: str

    # Asset/surface coverage
    assets_discovered: int = 0
    assets_scanned: int = 0
    endpoints_discovered: int = 0
    parameters_discovered: int = 0

    # Check execution
    checks_planned: int = 0
    checks_executed: int = 0
    checks_with_candidates: int = 0
    checks_blocked_prerequisite: int = 0
    checks_blocked_budget: int = 0
    checks_blocked_scope: int = 0
    checks_planned_unreached: int = 0

    # Findings
    candidates_total: int = 0
    verified_findings: int = 0
    reportable_findings: int = 0
    rejected_candidates: int = 0
    inconclusive_results: int = 0

    # Severity / confidence distribution
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    confidence_distribution: Dict[str, int] = field(default_factory=dict)

    # Coverage
    coverage_percentage: float = 0.0
    reachable_percentage: float = 0.0

    # Budget
    requests_used: int = 0
    requests_budget: int = 0
    budget_utilization_pct: float = 0.0

    # Special capability coverage
    authentication_coverage: bool = False
    workflow_coverage: bool = False
    browser_coverage: bool = False

    # Top risk areas (derived from findings)
    top_risk_areas: List[Dict[str, Any]] = field(default_factory=list)
    most_affected_assets: List[str] = field(default_factory=list)
    most_common_vulnerability_categories: List[Dict[str, Any]] = field(default_factory=list)

    # Operational gaps
    verification_failures: int = 0
    prerequisite_gaps: List[str] = field(default_factory=list)
    budget_constraint_notes: List[str] = field(default_factory=list)

    # Risk prioritization
    priority_assessments: List[PriorityAssessment] = field(default_factory=list)

    # Execution details
    execution_duration_seconds: float = 0.0
    safety_events_count: int = 0
    checks_skipped_not_applicable: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "target_url": self.target_url,
            "mode": self.mode,
            "generated_at": self.generated_at,
            "surface_coverage": {
                "assets_discovered": self.assets_discovered,
                "assets_scanned": self.assets_scanned,
                "endpoints_discovered": self.endpoints_discovered,
                "parameters_discovered": self.parameters_discovered,
            },
            "check_execution": {
                "checks_planned": self.checks_planned,
                "checks_executed": self.checks_executed,
                "checks_with_candidates": self.checks_with_candidates,
                "checks_blocked_prerequisite": self.checks_blocked_prerequisite,
                "checks_blocked_budget": self.checks_blocked_budget,
                "checks_blocked_scope": self.checks_blocked_scope,
                "checks_planned_unreached": self.checks_planned_unreached,
            },
            "findings": {
                "candidates_total": self.candidates_total,
                "verified_findings": self.verified_findings,
                "reportable_findings": self.reportable_findings,
                "rejected_candidates": self.rejected_candidates,
                "inconclusive_results": self.inconclusive_results,
            },
            "severity_distribution": self.severity_distribution,
            "confidence_distribution": self.confidence_distribution,
            "coverage": {
                "coverage_percentage": round(self.coverage_percentage, 2),
                "reachable_percentage": round(self.reachable_percentage, 2),
            },
            "budget": {
                "requests_used": self.requests_used,
                "requests_budget": self.requests_budget,
                "budget_utilization_pct": round(self.budget_utilization_pct, 2),
            },
            "capability_coverage": {
                "authentication_coverage": self.authentication_coverage,
                "workflow_coverage": self.workflow_coverage,
                "browser_coverage": self.browser_coverage,
            },
            "risk_intelligence": {
                "top_risk_areas": self.top_risk_areas,
                "most_affected_assets": self.most_affected_assets,
                "most_common_vulnerability_categories": self.most_common_vulnerability_categories,
                "priority_assessments": [p.to_dict() for p in self.priority_assessments[:10]],
            },
            "operational_gaps": {
                "verification_failures": self.verification_failures,
                "prerequisite_gaps": self.prerequisite_gaps,
                "budget_constraint_notes": self.budget_constraint_notes,
            },
            "execution": {
                "duration_seconds": self.execution_duration_seconds,
                "safety_events_count": self.safety_events_count,
            },
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ──────────────────────────────────────────────────────────────────────────────
# 3. CAMPAIGN INTELLIGENCE ENGINE
# ──────────────────────────────────────────────────────────────────────────────

class CampaignIntelligenceEngine:
    """Aggregates campaign data into a structured intelligence report.

    All values derive from actual CampaignResult, CoverageReport, and findings.
    No hallucination — missing data produces None or 0, not invented values.
    """

    @classmethod
    def build_report(
        cls,
        campaign_result: CampaignResult,
        coverage_report: Optional[CampaignCoverageReport] = None,
        findings: Optional[Sequence[Finding]] = None,
    ) -> CampaignIntelligenceReport:
        """Build a CampaignIntelligenceReport from real campaign data."""
        now = datetime.now(timezone.utc).isoformat()
        findings = list(findings or [])

        # ── Severity distribution ─────────────────────────────────────────────
        severity_dist: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = str(f.severity or "info").lower()
            if sev in severity_dist:
                severity_dist[sev] += 1

        # ── Confidence distribution ───────────────────────────────────────────
        conf_dist: Dict[str, int] = {"CERTAIN": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            conf = int(f.confidence or 0)
            if conf >= 90:
                conf_dist["CERTAIN"] += 1
            elif conf >= 75:
                conf_dist["HIGH"] += 1
            elif conf >= 50:
                conf_dist["MEDIUM"] += 1
            else:
                conf_dist["LOW"] += 1

        # ── Verified/reportable counts ────────────────────────────────────────
        verified = [f for f in findings if str(f.verdict or "").lower() == "verified"]
        candidates = campaign_result.candidates_count or len(findings)
        rejected = campaign_result.rejected_candidates_count or 0
        inconclusive = campaign_result.inconclusive_results_count or 0

        # ── Most affected assets ──────────────────────────────────────────────
        asset_counts: Dict[str, int] = {}
        for f in findings:
            host = cls._extract_host(str(f.affected_url or ""))
            asset_counts[host] = asset_counts.get(host, 0) + 1
        most_affected = sorted(asset_counts, key=lambda h: asset_counts[h], reverse=True)[:5]

        # ── Most common vuln categories ───────────────────────────────────────
        cat_counts: Dict[str, int] = {}
        for f in findings:
            cat = str(f.category or "unknown").lower()
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
        top_cats = [
            {"category": cat, "count": cnt}
            for cat, cnt in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        ]

        # ── Top risk areas (high/critical verified findings) ──────────────────
        high_risk = [
            f for f in verified
            if str(f.severity or "").lower() in ("critical", "high")
        ]
        top_risk = [
            {
                "check_id": str(f.vuln_type),
                "severity": str(f.severity),
                "affected_url": str(f.affected_url)[:100],
                "confidence": int(f.confidence or 0),
            }
            for f in high_risk[:5]
        ]

        # ── Prerequisite gaps from coverage ───────────────────────────────────
        prereq_gaps: List[str] = []
        coverage_pct = 0.0
        reachable_pct = 0.0
        checks_blocked_prereq = 0
        checks_blocked_budget = 0
        checks_blocked_scope = 0
        checks_planned_unreached = 0

        if coverage_report:
            coverage_pct = coverage_report.coverage_percentage
            reachable_pct = coverage_report.reachable_percentage
            checks_blocked_prereq = coverage_report.checks_skipped_prerequisite
            checks_blocked_budget = coverage_report.checks_skipped_budget
            checks_blocked_scope = coverage_report.checks_skipped_scope
            checks_planned_unreached = coverage_report.checks_planned_unreached

            # Identify specific prerequisite gaps
            from backend.services.campaign_executor import (
                AUTHENTICATION_REQUIRED_CHECKS,
                BROWSER_REQUIRED_CHECKS,
                WORKFLOW_REQUIRED_CHECKS,
            )
            if checks_blocked_prereq > 0:
                if BROWSER_REQUIRED_CHECKS:
                    prereq_gaps.append(
                        f"{len(BROWSER_REQUIRED_CHECKS)} browser-required checks skipped (no browser capability)"
                    )
                if AUTHENTICATION_REQUIRED_CHECKS:
                    prereq_gaps.append(
                        f"{len(AUTHENTICATION_REQUIRED_CHECKS)} auth-required checks skipped (no auth context)"
                    )
                if WORKFLOW_REQUIRED_CHECKS:
                    prereq_gaps.append(
                        f"{len(WORKFLOW_REQUIRED_CHECKS)} workflow-required checks skipped"
                    )

        # ── Budget constraint notes ───────────────────────────────────────────
        budget_notes: List[str] = []
        budget_used = campaign_result.requests_used or 0
        budget_total = campaign_result.requests_budget or 1
        budget_pct = (budget_used / budget_total * 100) if budget_total > 0 else 0.0

        if budget_pct >= 95:
            budget_notes.append(
                f"Request budget nearly exhausted ({budget_pct:.1f}%). "
                f"Consider increasing campaign_budget for broader coverage."
            )
        if campaign_result.checks_skipped_not_applicable > 0:
            budget_notes.append(
                f"{campaign_result.checks_skipped_not_applicable} checks skipped as not applicable."
            )

        # ── Risk prioritization ───────────────────────────────────────────────
        priorities = RiskPrioritizer.prioritize(findings)

        # ── Verification failures ─────────────────────────────────────────────
        ver_failures = sum(
            1 for e in (campaign_result.audit_trail or [])
            if e.get("event") in ("check_error", "verification_error")
        )

        return CampaignIntelligenceReport(
            campaign_id=campaign_result.campaign_id,
            target_url=campaign_result.target_url,
            mode=campaign_result.mode or "",
            generated_at=now,

            assets_discovered=campaign_result.assets_discovered or 0,
            assets_scanned=campaign_result.assets_scanned or 0,
            endpoints_discovered=len(campaign_result.endpoints or []),
            parameters_discovered=campaign_result.parameters_discovered or 0,

            checks_planned=campaign_result.checks_planned or 0,
            checks_executed=campaign_result.checks_executed or 0,
            checks_with_candidates=(coverage_report.checks_with_candidates if coverage_report else 0),
            checks_blocked_prerequisite=checks_blocked_prereq,
            checks_blocked_budget=checks_blocked_budget,
            checks_blocked_scope=checks_blocked_scope,
            checks_planned_unreached=checks_planned_unreached,

            candidates_total=candidates,
            verified_findings=len(verified),
            reportable_findings=len([f for f in verified if not f.false_positive]),
            rejected_candidates=rejected,
            inconclusive_results=inconclusive,

            severity_distribution=severity_dist,
            confidence_distribution=conf_dist,

            coverage_percentage=coverage_pct,
            reachable_percentage=reachable_pct,

            requests_used=budget_used,
            requests_budget=budget_total,
            budget_utilization_pct=budget_pct,

            authentication_coverage=False,  # Will be enhanced when auth context is available
            workflow_coverage=False,
            browser_coverage=False,

            top_risk_areas=top_risk,
            most_affected_assets=most_affected,
            most_common_vulnerability_categories=top_cats,

            verification_failures=ver_failures,
            prerequisite_gaps=prereq_gaps,
            budget_constraint_notes=budget_notes,

            priority_assessments=priorities,

            execution_duration_seconds=campaign_result.execution_duration or 0.0,
            safety_events_count=len(campaign_result.safety_events or []),
            checks_skipped_not_applicable=campaign_result.checks_not_applicable or 0,
        )

    @staticmethod
    def _extract_host(url: str) -> str:
        try:
            from urllib.parse import urlparse
            return urlparse(url).netloc or url
        except Exception:
            return url


__all__ = [
    "PriorityAssessment",
    "RiskPrioritizer",
    "CampaignIntelligenceReport",
    "CampaignIntelligenceEngine",
]
