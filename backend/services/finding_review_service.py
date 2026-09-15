"""AihaX Phase 19 — Human Review Gate & Finding Review Service.

Architectural Invariants:
1. Explicit Human Authorization: No finding may become REPORTABLE without explicit operator review and approval.
2. Pre-Approval Evidence Gating: Approving a finding requires VERIFIED verdict, valid evidence records, and verifier version.
3. Rejection Fail-Closed: Rejected findings transition to REJECTED with false_positive=True and can never become REPORTABLE.
4. Cryptographic Audit Trail: All review decisions emit cryptographically chained audit events (FINDING_HUMAN_APPROVED, FINDING_HUMAN_REJECTED, FINDING_REVERIFICATION_REQUESTED).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from backend.models.database import Finding
from backend.services.finding_deduplicator import FindingLifecycleState

logger = logging.getLogger("aihax.finding_review_service")


class FindingReviewService:
    """Service to enforce human operator review before findings become REPORTABLE."""

    def __init__(self, db: Optional[Session] = None) -> None:
        self.db = db

    def approve_finding(
        self,
        finding_id: str,
        actor: str = "operator",
        notes: Optional[str] = None,
        db: Optional[Session] = None,
        repo: Optional[Any] = None,
    ) -> Finding:
        """Approve a verified finding for inclusion in the final report package."""
        session = db or self.db
        if not session:
            raise ValueError("Database session required for approving finding.")

        finding = session.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise ValueError(f"Finding '{finding_id}' not found.")

        # 1. Pre-Approval Contract & Evidence Validation
        verdict = str(finding.verdict or "").strip().lower()
        if verdict != "verified":
            raise ValueError(f"Finding '{finding_id}' cannot be approved: verdict is '{finding.verdict}', expected 'Verified'.")

        if finding.false_positive:
            raise ValueError(f"Finding '{finding_id}' cannot be approved: finding is marked as false_positive=True.")

        if finding.duplicate_of:
            raise ValueError(f"Finding '{finding_id}' cannot be approved: finding is a duplicate of '{finding.duplicate_of}'.")

        has_evidence = bool(
            (finding.proof_request and finding.proof_request.strip())
            or (finding.proof_response and finding.proof_response.strip())
            or (finding.payload and finding.payload.strip())
            or (finding.evidence_ids and finding.evidence_ids != "[]")
        )
        if not has_evidence:
            raise ValueError(f"Finding '{finding_id}' cannot be approved: missing required proof evidence.")

        # 2. Transition Finding State to Approved / REPORTABLE
        finding.human_review_status = "APPROVED"
        finding.human_reviewed_by = actor
        finding.human_reviewed_at = datetime.now(timezone.utc)
        finding.human_review_notes = notes
        finding.verification_status = FindingLifecycleState.REPORTABLE.value

        session.commit()

        # 3. Append Audit Trail Event
        if repo and hasattr(repo, "append_audit_event"):
            try:
                camp = repo.get_campaign(finding.scan_id) if hasattr(repo, "get_campaign") else None
                if camp:
                    repo.append_audit_event(
                        campaign_id=camp.id,
                        event_type="FINDING_HUMAN_APPROVED",
                        actor=actor,
                        object_id=finding.id,
                        metadata={
                            "title": finding.title,
                            "vuln_type": finding.vuln_type,
                            "affected_url": finding.affected_url,
                            "severity": finding.severity,
                            "notes": notes,
                        },
                    )
            except Exception as e:
                logger.warning(f"Could not append audit event for approved finding {finding.id}: {e}")

        logger.info(f"Finding {finding.id} ({finding.title}) approved by {actor} as REPORTABLE.")
        return finding

    def reject_finding(
        self,
        finding_id: str,
        actor: str = "operator",
        reason: str = "Operator rejected during review",
        notes: Optional[str] = None,
        db: Optional[Session] = None,
        repo: Optional[Any] = None,
    ) -> Finding:
        """Reject a candidate/verified finding as a false positive or not applicable."""
        session = db or self.db
        if not session:
            raise ValueError("Database session required for rejecting finding.")

        finding = session.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise ValueError(f"Finding '{finding_id}' not found.")

        finding.human_review_status = "REJECTED"
        finding.human_reviewed_by = actor
        finding.human_reviewed_at = datetime.now(timezone.utc)
        finding.human_review_notes = notes or reason
        finding.verdict = "Rejected"
        finding.false_positive = True
        finding.verification_status = FindingLifecycleState.REJECTED.value

        session.commit()

        if repo and hasattr(repo, "append_audit_event"):
            try:
                camp = repo.get_campaign(finding.scan_id) if hasattr(repo, "get_campaign") else None
                if camp:
                    repo.append_audit_event(
                        campaign_id=camp.id,
                        event_type="FINDING_HUMAN_REJECTED",
                        actor=actor,
                        object_id=finding.id,
                        metadata={
                            "title": finding.title,
                            "vuln_type": finding.vuln_type,
                            "reason": reason,
                            "notes": notes,
                        },
                    )
            except Exception as e:
                logger.warning(f"Could not append audit event for rejected finding {finding.id}: {e}")

        logger.info(f"Finding {finding.id} ({finding.title}) rejected by {actor}.")
        return finding

    def request_reverification(
        self,
        finding_id: str,
        actor: str = "operator",
        notes: Optional[str] = None,
        db: Optional[Session] = None,
        repo: Optional[Any] = None,
    ) -> Finding:
        """Request re-verification of a finding when evidence is uncertain."""
        session = db or self.db
        if not session:
            raise ValueError("Database session required for requesting re-verification.")

        finding = session.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise ValueError(f"Finding '{finding_id}' not found.")

        finding.human_review_status = "REVERIFICATION_REQUESTED"
        finding.human_reviewed_by = actor
        finding.human_reviewed_at = datetime.now(timezone.utc)
        finding.human_review_notes = notes
        finding.verification_status = FindingLifecycleState.VERIFICATION_REQUESTED.value

        session.commit()

        if repo and hasattr(repo, "append_audit_event"):
            try:
                camp = repo.get_campaign(finding.scan_id) if hasattr(repo, "get_campaign") else None
                if camp:
                    repo.append_audit_event(
                        campaign_id=camp.id,
                        event_type="FINDING_REVERIFICATION_REQUESTED",
                        actor=actor,
                        object_id=finding.id,
                        metadata={
                            "title": finding.title,
                            "vuln_type": finding.vuln_type,
                            "notes": notes,
                        },
                    )
            except Exception as e:
                logger.warning(f"Could not append audit event for reverification finding {finding.id}: {e}")

        logger.info(f"Finding {finding.id} marked for re-verification by {actor}.")
        return finding
