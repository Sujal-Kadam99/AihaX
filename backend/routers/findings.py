"""Findings and report API routes."""

import json
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.models.database import Finding, Scan, get_db
from backend.models.schemas import FindingResponse

router = APIRouter(tags=["findings"])


@router.get("/api/findings/{scan_id}")
async def get_findings(
    scan_id: str,
    severity: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    if scan_id.lower() == "all":
        query = db.query(Finding).filter(Finding.false_positive == False)
    else:
        query = db.query(Finding).filter(
            (Finding.scan_id == scan_id) | (Finding.chain_id == scan_id),
            Finding.false_positive == False
        )
    if severity:
        query = query.filter_by(severity=severity)
    findings = query.order_by(Finding.created_at.desc()).all()

    return [
        FindingResponse(
            id=f.id,
            scan_id=f.scan_id,
            title=f.title,
            vuln_type=f.vuln_type,
            category=f.category,
            severity=f.severity,
            cvss_score=f.cvss_score,
            cwe_id=f.cwe_id,
            cve_id=f.cve_id,
            affected_url=f.affected_url,
            affected_param=f.affected_param,
            payload=f.payload,
            proof_response=f.proof_response,
            screenshot_path=f.screenshot_path,
            confidence=f.confidence,
            verdict=f.verdict,
            verification_status=f.verification_status,
            verification_reason_code=f.verification_reason_code,
            verification_method=f.verification_method,
            verification_timestamp=f.verification_timestamp,
            false_positive=f.false_positive,
            agent_id=f.agent_id,
            remediation=json.loads(f.remediation) if f.remediation else None,
            business_impact=json.loads(f.business_impact) if f.business_impact else None,
            human_review_status=getattr(f, "human_review_status", "PENDING"),
            human_reviewed_by=getattr(f, "human_reviewed_by", None),
            human_reviewed_at=getattr(f, "human_reviewed_at", None),
            human_review_notes=getattr(f, "human_review_notes", None),
            duplicate_of=getattr(f, "duplicate_of", None),
            finding_fingerprint=getattr(f, "finding_fingerprint", None),
            finding_disposition=getattr(f, "finding_disposition", "INCONCLUSIVE"),
            condition_confidence=getattr(f, "condition_confidence", 0.0),
            impact_confidence=getattr(f, "impact_confidence", 0.0),
            reproducibility_confidence=getattr(f, "reproducibility_confidence", 0.0),
            exploitability_confidence=getattr(f, "exploitability_confidence", 0.0),
            policy_eligibility_confidence=getattr(f, "policy_eligibility_confidence", 0.0),
            bounty_eligibility=getattr(f, "bounty_eligibility", "UNKNOWN"),
            verification_explanation=getattr(f, "verification_explanation", None),
            created_at=f.created_at,
        )
        for f in findings
    ]


@router.get("/api/findings/pending-review/{scan_id}")
async def get_pending_review_findings(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve verified findings awaiting operator human review."""
    query = db.query(Finding).filter(
        (Finding.scan_id == scan_id) | (Finding.chain_id == scan_id),
        Finding.verdict == "Verified",
        Finding.false_positive == False,
        Finding.duplicate_of == None,
        (Finding.human_review_status == "PENDING") | (Finding.human_review_status == None),
    )
    findings = query.order_by(Finding.confidence.desc(), Finding.created_at.asc()).all()

    return [
        FindingResponse(
            id=f.id,
            scan_id=f.scan_id,
            title=f.title,
            vuln_type=f.vuln_type,
            category=f.category,
            severity=f.severity,
            cvss_score=f.cvss_score,
            cwe_id=f.cwe_id,
            cve_id=f.cve_id,
            affected_url=f.affected_url,
            affected_param=f.affected_param,
            payload=f.payload,
            proof_response=f.proof_response,
            screenshot_path=f.screenshot_path,
            confidence=f.confidence,
            verdict=f.verdict,
            verification_status=f.verification_status,
            verification_reason_code=f.verification_reason_code,
            verification_method=f.verification_method,
            verification_timestamp=f.verification_timestamp,
            false_positive=f.false_positive,
            agent_id=f.agent_id,
            remediation=json.loads(f.remediation) if f.remediation else None,
            business_impact=json.loads(f.business_impact) if f.business_impact else None,
            human_review_status=getattr(f, "human_review_status", "PENDING"),
            human_reviewed_by=getattr(f, "human_reviewed_by", None),
            human_reviewed_at=getattr(f, "human_reviewed_at", None),
            human_review_notes=getattr(f, "human_review_notes", None),
            duplicate_of=getattr(f, "duplicate_of", None),
            finding_fingerprint=getattr(f, "finding_fingerprint", None),
            created_at=f.created_at,
        )
        for f in findings
    ]


@router.post("/api/findings/{finding_id}/review")
async def review_finding(
    finding_id: str,
    payload: dict,
    db: Session = Depends(get_db),
):
    """Operator human review gate: Approve, Reject, or Request Re-verification."""
    from backend.persistence.repository import CampaignRepository
    from backend.services.finding_review_service import FindingReviewService

    repo = CampaignRepository(db)
    service = FindingReviewService(db)

    decision = str(payload.get("decision", "")).strip().upper()
    notes = payload.get("notes")
    actor = str(payload.get("actor", "operator")).strip() or "operator"

    try:
        if decision in ("APPROVE", "APPROVE_REPORT"):
            updated = service.approve_finding(finding_id=finding_id, actor=actor, notes=notes, db=db, repo=repo)
        elif decision in ("REJECT", "REJECT_REPORT"):
            reason = str(payload.get("reason") or notes or "Operator rejected finding")
            updated = service.reject_finding(finding_id=finding_id, actor=actor, reason=reason, notes=notes, db=db, repo=repo)
        elif decision in ("REVERIFY", "REQUEST_REVERIFICATION"):
            updated = service.request_reverification(finding_id=finding_id, actor=actor, notes=notes, db=db, repo=repo)
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid review decision '{decision}'. Expected APPROVE, REJECT, or REVERIFY.",
            )

        return {
            "success": True,
            "data": {
                "id": updated.id,
                "title": updated.title,
                "human_review_status": updated.human_review_status,
                "verification_status": updated.verification_status,
                "verdict": updated.verdict,
                "false_positive": updated.false_positive,
            },
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Review operation failed: {str(e)}")


@router.get("/api/findings/detail/{finding_id}")
async def get_finding_detail(
    finding_id: str,
    db: Session = Depends(get_db),
):
    f = db.query(Finding).filter_by(id=finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    return FindingResponse(
        id=f.id,
        scan_id=f.scan_id,
        title=f.title,
        vuln_type=f.vuln_type,
        category=f.category,
        severity=f.severity,
        cvss_score=f.cvss_score,
        cwe_id=f.cwe_id,
        cve_id=f.cve_id,
        affected_url=f.affected_url,
        affected_param=f.affected_param,
        payload=f.payload,
        proof_response=f.proof_response,
        screenshot_path=f.screenshot_path,
        confidence=f.confidence,
        verdict=f.verdict,
        verification_status=f.verification_status,
        verification_reason_code=f.verification_reason_code,
        verification_method=f.verification_method,
        verification_timestamp=f.verification_timestamp,
        false_positive=f.false_positive,
        agent_id=f.agent_id,
        remediation=json.loads(f.remediation) if f.remediation else None,
        business_impact=json.loads(f.business_impact) if f.business_impact else None,
        human_review_status=getattr(f, "human_review_status", "PENDING"),
        human_reviewed_by=getattr(f, "human_reviewed_by", None),
        human_reviewed_at=getattr(f, "human_reviewed_at", None),
        human_review_notes=getattr(f, "human_review_notes", None),
        duplicate_of=getattr(f, "duplicate_of", None),
        finding_fingerprint=getattr(f, "finding_fingerprint", None),
        finding_disposition=getattr(f, "finding_disposition", "INCONCLUSIVE"),
        condition_confidence=getattr(f, "condition_confidence", 0.0),
        impact_confidence=getattr(f, "impact_confidence", 0.0),
        reproducibility_confidence=getattr(f, "reproducibility_confidence", 0.0),
        exploitability_confidence=getattr(f, "exploitability_confidence", 0.0),
        policy_eligibility_confidence=getattr(f, "policy_eligibility_confidence", 0.0),
        bounty_eligibility=getattr(f, "bounty_eligibility", "UNKNOWN"),
        verification_explanation=getattr(f, "verification_explanation", None),
        created_at=f.created_at,
    )


@router.get("/api/report/{scan_id}")
async def download_report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    settings = get_settings()
    reports_dir = Path(settings.reports_path).resolve()
    report_path = (reports_dir / f"{scan_id}.pdf").resolve()

    # Prevent path traversal
    if not str(report_path).startswith(str(reports_dir)):
        raise HTTPException(status_code=400, detail="Invalid report path")

    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not yet generated")

    return FileResponse(
        report_path,
        media_type="application/pdf",
        filename=f"aihax-report-{scan_id[:8]}.pdf",
    )
