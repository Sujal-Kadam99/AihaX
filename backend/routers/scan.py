"""Scan management API routes."""

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.agents.base_agent import AGENT_NAMES
from backend.core.config import get_settings
from backend.core.rate_limit import check_scan_rate_limit
from backend.core.redis_client import get_agent_state, get_scan_status, set_scan_status
from backend.core.entitlements import get_user_tier
from backend.models.database import Finding, Scan, get_db
from backend.models.schemas import (
    AgentStatus,
    FindingsCount,
    ScanConfig,
    ScanHistoryItem,
    ScanStatus,
)
from backend.services.orchestrator import run_scan_pipeline, save_scan_config

router = APIRouter(prefix="/api/scan", tags=["scan"])


@router.post("/start")
async def start_scan(
    config: ScanConfig,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db),
    tier: str = Depends(get_user_tier),
):
    settings = get_settings()

    # The scan profile and quota exemptions are granted only by a verified,
    # signed entitlement. A localhost request or client-supplied admin_mode
    # flag is not proof of an owner or paid account.
    from backend.core.auth import get_user_context

    user_ctx = get_user_context(request)
    user_email = user_ctx.get("email")
    user_id = user_ctx.get("user_id")

    if tier == "founder":
        # Force best results, bypass all limits
        config.scan_depth = "deep"
        config.threads = 20
        config.waf_bypass = True
        config.stealth_mode = False
    else:
        # Prevent free users from using advanced features
        if tier == "free":
            if config.admin_mode or config.waf_bypass or config.scan_depth == "deep":
                raise HTTPException(status_code=403, detail="Advanced features like admin_mode, deep scan, and waf_bypass require a Pro subscription.")
        
        # --- Freemium: limit free users to 3 scans per month ---
        if tier == "free":
            now = datetime.now(timezone.utc)
            month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

            query = db.query(Scan).filter(
                Scan.created_at >= month_start,
                Scan.status != "cancelled",
            )

            if user_email:
                query = query.filter(Scan.user_email == user_email)
            else:
                client_ip = request.client.host if request.client else "unknown"
                query = query.filter(Scan.user_email == client_ip)

            monthly_scans = query.count()

            free_limit = settings.free_tier_monthly_scans
            if tier == "free" and monthly_scans >= free_limit:
                raise HTTPException(
                    status_code=402,
                    detail=(
                        f"Free tier limit ({free_limit} scans/month) reached. "
                        "Please upgrade to Pro for unlimited scans."
                    ),
                )

        check_scan_rate_limit(request.client.host if request.client else "default")

    # Scope validation if program_id provided
    if config.program_id:
        import json
        from backend.core.scope_validator import ScopeValidator
        from backend.models.database import ProgramScope

        prog_scope = db.query(ProgramScope).filter_by(program_id=config.program_id).first()
        if prog_scope:
            in_assets = json.loads(prog_scope.in_scope_assets or "[]")
            out_assets = json.loads(prog_scope.out_of_scope_assets or "[]")
            allowed_p = json.loads(prog_scope.allowed_ports or "[]")
            excluded_p = json.loads(prog_scope.excluded_ports or "[]")
            allowed_s = json.loads(prog_scope.allowed_schemes or '["http", "https"]')
            excluded_paths = json.loads(prog_scope.excluded_paths or "[]")
            validator = ScopeValidator(
                in_scope_assets=in_assets,
                out_of_scope_assets=out_assets,
                allowed_ports=allowed_p if allowed_p else None,
                excluded_ports=excluded_p if excluded_p else None,
                allowed_schemes=allowed_s,
                excluded_paths=excluded_paths,
            )
            decision = validator.is_url_in_scope(config.target_url)
            if not decision.allowed:
                raise HTTPException(
                    status_code=400,
                    detail=f"Target URL '{config.target_url}' is not in authorized program scope: {decision.reason}",
                )

    rps = config.rate_limit.requests_per_second if config.rate_limit else 10
    concurrency = config.rate_limit.max_concurrency if config.rate_limit else 5

    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        target_url=config.target_url,
        status="pending",
        scan_depth=config.scan_depth,
        scan_mode=config.scan_mode,
        threads=config.threads,
        waf_bypass=config.waf_bypass,
        stealth_mode=config.stealth_mode,
        industry=config.industry,
        admin_mode=config.admin_mode,
        program_id=config.program_id,
        rate_limit_rps=rps,
        max_concurrency=concurrency,
        user_id=user_id,
        user_email=user_email if user_email else (request.client.host if request.client else None),
    )
    db.add(scan)
    db.commit()

    config_dict = config.model_dump()
    config_dict["rate_limit_rps"] = rps
    config_dict["max_concurrency"] = concurrency
    if config.primary_creds:
        config_dict["primary_creds"] = config.primary_creds.model_dump()
    if config.secondary_creds:
        config_dict["secondary_creds"] = config.secondary_creds.model_dump()
    if config.email_creds:
        config_dict["email_creds"] = config.email_creds.model_dump()
    if config.two_fa_config:
        config_dict["two_fa_config"] = config.two_fa_config.model_dump()
    if config.api_auth:
        config_dict["api_auth"] = config.api_auth.model_dump()
    if config.scope_notes is not None:
        config_dict["scope_notes"] = config.scope_notes
    config_dict["authorization_confirmed"] = config.authorization_confirmed

    save_scan_config(db, scan_id, config_dict)
    background_tasks.add_task(run_scan_pipeline, scan_id, config_dict)

    return {"scan_id": scan_id, "status": "pending", "message": "Scan started"}


@router.get("/history/list")
async def scan_history(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(50).all()
    return [
        ScanHistoryItem(
            id=s.id,
            target_url=s.target_url,
            created_at=s.created_at,
            completed_at=s.completed_at,
            status=s.status,
            scan_depth=s.scan_depth,
            scan_mode=s.scan_mode,
            total_findings=s.total_findings or 0,
            risk_score=s.risk_score,
            admin_mode=s.admin_mode,
        )
        for s in scans
    ]


@router.get("/{scan_id}")
async def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    agents = []
    for agent_id, agent_name in AGENT_NAMES.items():
        state = await get_agent_state(scan_id, agent_id)
        agents.append(AgentStatus(
            agent_id=agent_id,
            agent_name=agent_name,
            status=state.get("status", "pending"),
            progress=int(state.get("progress", 0)),
            message=state.get("message", ""),
        ))

    findings = db.query(Finding).filter_by(scan_id=scan_id, false_positive=False).all()
    counts = FindingsCount()
    for f in findings:
        setattr(counts, f.severity, getattr(counts, f.severity, 0) + 1)

    elapsed = 0
    if scan.created_at:
        from datetime import timezone
        end = scan.completed_at or datetime.utcnow().replace(tzinfo=timezone.utc)
        elapsed = int((end - scan.created_at).total_seconds())

    return ScanStatus(
        scan_id=scan.id,
        target_url=scan.target_url,
        status=scan.status,
        agents=agents,
        findings_count=counts,
        elapsed_seconds=elapsed,
        risk_score=scan.risk_score,
        created_at=scan.created_at,
        admin_mode=scan.admin_mode,
    )


@router.delete("/{scan_id}")
async def cancel_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    await set_scan_status(scan_id, "cancelled")
    scan.status = "cancelled"
    db.commit()
    return {"scan_id": scan_id, "status": "cancelled"}


