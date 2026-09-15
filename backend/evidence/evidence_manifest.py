"""AihaX Phase 8 — Campaign Cryptographic Manifest & Integrity Verifier.

Anchors all campaign artifacts into a deterministic, verifiable cryptographic manifest:
- Scope hash
- Configuration snapshot hash
- Execution graph hash
- Evidence manifest hash (sorted SHA-256 hashes of all evidence items)
- Finding manifest hash (sorted SHA-256 hashes of all finding evidence)
- Coverage report hash
- Bug bounty report hashes

Provides `verify_campaign_integrity()` which produces a structured integrity report.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.persistence.repository import CampaignRepository

logger = logging.getLogger(__name__)


@dataclass
class IntegrityCheckResult:
    check_name: str
    passed: bool
    details: str
    expected: Optional[str] = None
    actual: Optional[str] = None


@dataclass
class CampaignIntegrityReport:
    campaign_id: str
    verified: bool
    checked_at: str
    checks: List[IntegrityCheckResult] = field(default_factory=list)
    manifest_hash: Optional[str] = None
    issues: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "verified": self.verified,
            "checked_at": self.checked_at,
            "manifest_hash": self.manifest_hash,
            "issues": self.issues,
            "checks": [
                {
                    "check_name": c.check_name,
                    "passed": c.passed,
                    "details": c.details,
                    "expected": c.expected,
                    "actual": c.actual,
                }
                for c in self.checks
            ],
        }


@dataclass
class CampaignManifest:
    campaign_id: str
    scope_hash: str
    config_hash: str
    execution_graph_hash: str
    evidence_hashes: List[str]
    finding_hashes: List[str]
    coverage_report_hash: str
    report_hashes: List[str]
    manifest_hash: str
    generated_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "scope_hash": self.scope_hash,
            "config_hash": self.config_hash,
            "execution_graph_hash": self.execution_graph_hash,
            "evidence_hashes": self.evidence_hashes,
            "finding_hashes": self.finding_hashes,
            "coverage_report_hash": self.coverage_report_hash,
            "report_hashes": self.report_hashes,
            "manifest_hash": self.manifest_hash,
            "generated_at": self.generated_at,
        }


def compute_manifest_hash(
    campaign_id: str,
    scope_hash: str,
    config_hash: str,
    execution_graph_hash: str,
    evidence_hashes: List[str],
    finding_hashes: List[str],
    coverage_report_hash: str,
    report_hashes: List[str],
) -> str:
    """Compute top-level SHA-256 root hash over all campaign component hashes."""
    canonical = {
        "campaign_id": campaign_id,
        "scope_hash": scope_hash,
        "config_hash": config_hash,
        "execution_graph_hash": execution_graph_hash,
        "evidence_hashes": sorted(evidence_hashes),
        "finding_hashes": sorted(finding_hashes),
        "coverage_report_hash": coverage_report_hash,
        "report_hashes": sorted(report_hashes),
    }
    raw = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class ManifestBuilder:
    """Builds and verifies cryptographic campaign manifests."""

    @staticmethod
    def build_manifest(
        campaign_id: str,
        scope_hash: str = "",
        config_hash: str = "",
        execution_graph_hash: str = "",
        evidence_hashes: Optional[List[str]] = None,
        finding_hashes: Optional[List[str]] = None,
        coverage_report_hash: str = "",
        report_hashes: Optional[List[str]] = None,
    ) -> CampaignManifest:
        ev_hashes = list(evidence_hashes or [])
        f_hashes = list(finding_hashes or [])
        rep_hashes = list(report_hashes or [])
        now_str = datetime.now(timezone.utc).isoformat()

        root_hash = compute_manifest_hash(
            campaign_id=campaign_id,
            scope_hash=scope_hash,
            config_hash=config_hash,
            execution_graph_hash=execution_graph_hash,
            evidence_hashes=ev_hashes,
            finding_hashes=f_hashes,
            coverage_report_hash=coverage_report_hash,
            report_hashes=rep_hashes,
        )

        return CampaignManifest(
            campaign_id=campaign_id,
            scope_hash=scope_hash,
            config_hash=config_hash,
            execution_graph_hash=execution_graph_hash,
            evidence_hashes=sorted(ev_hashes),
            finding_hashes=sorted(f_hashes),
            coverage_report_hash=coverage_report_hash,
            report_hashes=sorted(rep_hashes),
            manifest_hash=root_hash,
            generated_at=now_str,
        )

    @staticmethod
    def verify_campaign_integrity(
        repository: CampaignRepository,
        campaign_id: str,
    ) -> CampaignIntegrityReport:
        """Perform comprehensive cryptographic integrity verification of a campaign."""
        checks: List[IntegrityCheckResult] = []
        issues: List[str] = []
        now_str = datetime.now(timezone.utc).isoformat()

        campaign = repository.get_campaign(campaign_id)
        if not campaign:
            return CampaignIntegrityReport(
                campaign_id=campaign_id,
                verified=False,
                checked_at=now_str,
                checks=[IntegrityCheckResult("campaign_exists", False, f"Campaign '{campaign_id}' not found in database")],
                issues=[f"Campaign '{campaign_id}' does not exist."],
            )

        checks.append(IntegrityCheckResult("campaign_exists", True, "Campaign record found"))

        # 1. Check authorization record
        auth = repository.get_authorization(campaign_id)
        if not auth:
            passed = False
            details = "Missing authorization record"
            issues.append("Campaign lacks authorization record.")
        elif auth.status != "ACTIVE" or (auth.expires_at and auth.expires_at < datetime.now(timezone.utc)):
            passed = False
            details = f"Authorization is {auth.status} or expired at {auth.expires_at}"
            issues.append(f"Authorization invalid or expired.")
        else:
            passed = True
            details = f"Active authorization verified (authorized by {auth.authorized_by})"
        checks.append(IntegrityCheckResult("authorization_valid", passed, details))

        # 2. Check snapshot integrity
        snapshot = repository.get_snapshot(campaign_id)
        if snapshot:
            computed_snap_hash = hashlib.sha256(snapshot.snapshot_json.encode("utf-8")).hexdigest()
            snap_match = computed_snap_hash == snapshot.snapshot_hash
            checks.append(IntegrityCheckResult(
                "snapshot_integrity",
                snap_match,
                "Snapshot hash matches" if snap_match else "Snapshot hash mismatch",
                expected=snapshot.snapshot_hash,
                actual=computed_snap_hash,
            ))
            if not snap_match:
                issues.append("Campaign configuration snapshot hash does not match computed hash.")
        else:
            checks.append(IntegrityCheckResult("snapshot_integrity", True, "No snapshot saved (draft/initial state)"))

        # 3. Check evidence vault items integrity
        evidence_records = repository.get_evidence_for_campaign(campaign_id, limit=500)
        ev_hashes: List[str] = []
        ev_intact = True
        for rec in evidence_records:
            ev_hashes.append(rec.content_hash)
            from backend.evidence.integrity import verify_evidence_integrity
            valid, reason = verify_evidence_integrity(
                content_hash=rec.content_hash,
                evidence_type=rec.evidence_type,
                target_url=rec.target_url,
                method=rec.method,
                sanitized_request=rec.sanitized_request,
                sanitized_response=rec.sanitized_response,
                payload_summary=rec.payload_summary,
            )
            if not valid:
                ev_intact = False
                issues.append(f"Evidence {rec.id} corrupted: {reason}")

        checks.append(IntegrityCheckResult(
            "evidence_vault_integrity",
            ev_intact,
            f"{len(evidence_records)} evidence items verified" if ev_intact else "Corrupted evidence items found",
        ))

        # 4. Check audit log hash chaining
        audit_events = repository.get_audit_trail(campaign_id)
        audit_intact = True
        prev_hash: Optional[str] = None
        for ev in audit_events:
            from backend.persistence.repository import _compute_event_hash
            ts_str = ev.timestamp.isoformat() if hasattr(ev.timestamp, "isoformat") else str(ev.timestamp)
            expected_ev_hash = _compute_event_hash(
                campaign_id=ev.campaign_id,
                event_type=ev.event_type,
                actor=ev.actor,
                timestamp_str=ts_str,
                metadata_json=ev.metadata_json,
                previous_hash=prev_hash,
            )
            if ev.previous_event_hash != prev_hash or ev.event_hash != expected_ev_hash:
                audit_intact = False
                issues.append(f"Audit log tampering detected at event {ev.id} ({ev.event_type})")
            prev_hash = ev.event_hash

        checks.append(IntegrityCheckResult(
            "audit_trail_chaining",
            audit_intact,
            f"{len(audit_events)} audit events verified with hash chaining" if audit_intact else "Audit log hash chaining violated",
        ))

        overall_passed = all(c.passed for c in checks) and len(issues) == 0

        return CampaignIntegrityReport(
            campaign_id=campaign_id,
            verified=overall_passed,
            checked_at=now_str,
            checks=checks,
            manifest_hash=campaign.manifest_hash,
            issues=issues,
        )
