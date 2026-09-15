from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from backend.core.auth import _is_local_request
from backend.models.database import get_db, Scan
from backend.persistence.models import Campaign
from backend.services.report_generator import generate_scan_report

router = APIRouter()


@router.get("/scan/{scan_id}")
@router.get("/campaign/{scan_id}")
def download_scan_report(
    scan_id: str,
    request: Request,
    mode: str | None = None,
    db: Session = Depends(get_db),
):
    """Generate and download a PDF report for a completed scan or campaign."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    campaign = None
    if not scan:
        campaign = db.query(Campaign).filter(Campaign.id == scan_id).first()
        if not campaign:
            raise HTTPException(status_code=404, detail=f"Report target '{scan_id}' not found")

    target_obj = scan or campaign

    # Only enforce user ownership when NOT running locally
    if not _is_local_request(request):
        from backend.core.auth import get_user_context
        ctx = get_user_context(request)
        if ctx.get("user_id") and getattr(target_obj, "user_id", None) and ctx["user_id"] != target_obj.user_id:
            raise HTTPException(status_code=403, detail="Not authorized to access this report")

    # If Scan, verify it is at least started/completed
    if scan and scan.status not in ("complete", "completed", "failed", "error", "running"):
        raise HTTPException(
            status_code=400,
            detail=f"Scan is not ready for report generation (current status: {scan.status})"
        )

    try:
        pdf_bytes = generate_scan_report(db, scan_id, mode=mode)

        headers = {
            "Content-Disposition": f"attachment; filename=aihax-report-{scan_id[:8]}.pdf"
        }

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers=headers,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")
