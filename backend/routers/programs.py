"""Bug Bounty Program and Scope Management API routes."""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.core.auth import get_user_context
from backend.core.scope_validator import ScopeValidator
from backend.models.database import Program, ProgramScope, get_db
from backend.models.schemas import (
    ProgramCreate,
    ProgramResponse,
    ScopeDefinitionSchema,
    ScopeValidationRequest,
    ScopeValidationResponse,
)

router = APIRouter(prefix="/api/programs", tags=["programs"])


def _parse_scope_model_to_schema(scope: ProgramScope | None) -> ScopeDefinitionSchema | None:
    if not scope:
        return None
    return ScopeDefinitionSchema(
        in_scope_assets=json.loads(scope.in_scope_assets or "[]"),
        out_of_scope_assets=json.loads(scope.out_of_scope_assets or "[]"),
        allowed_ports=json.loads(scope.allowed_ports or "[]"),
        excluded_ports=json.loads(scope.excluded_ports or "[]"),
        allowed_schemes=json.loads(scope.allowed_schemes or '["http", "https"]'),
        excluded_paths=json.loads(scope.excluded_paths or "[]"),
        scope_notes=scope.scope_notes,
    )


def _build_program_response(program: Program, db: Session) -> ProgramResponse:
    from backend.persistence.models import Campaign

    campaigns = db.query(Campaign).filter(Campaign.program_id == program.id).all()
    active_count = sum(1 for c in campaigns if c.status in ["RUNNING", "PAUSED", "QUEUED", "AUTHORIZED"])
    campaigns_summary = [
        {
            "id": c.id,
            "name": c.name,
            "status": c.status,
            "target_url": c.target_url,
            "created_at": c.created_at.isoformat() if hasattr(c.created_at, "isoformat") else str(c.created_at),
        }
        for c in campaigns
    ]

    return ProgramResponse(
        id=program.id,
        name=program.name,
        description=program.description,
        user_id=program.user_id,
        status="AUTHORIZED",
        active_campaigns_count=active_count,
        total_campaigns_count=len(campaigns),
        campaigns=campaigns_summary,
        scope=_parse_scope_model_to_schema(program.scope),
        created_at=program.created_at,
    )


@router.post("", response_model=ProgramResponse)
async def create_program(
    payload: ProgramCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    user_ctx = get_user_context(request)
    user_id = user_ctx.get("user_id")

    program_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    program = Program(
        id=program_id,
        name=payload.name.strip(),
        description=payload.description.strip() if payload.description else None,
        user_id=user_id,
        created_at=now,
    )
    db.add(program)

    scope_data = payload.scope or ScopeDefinitionSchema()
    prog_scope = ProgramScope(
        id=str(uuid.uuid4()),
        program_id=program_id,
        in_scope_assets=json.dumps(scope_data.in_scope_assets),
        out_of_scope_assets=json.dumps(scope_data.out_of_scope_assets),
        allowed_ports=json.dumps(scope_data.allowed_ports),
        excluded_ports=json.dumps(scope_data.excluded_ports),
        allowed_schemes=json.dumps(scope_data.allowed_schemes),
        excluded_paths=json.dumps(scope_data.excluded_paths),
        scope_notes=scope_data.scope_notes,
        created_at=now,
        updated_at=now,
    )
    db.add(prog_scope)
    db.commit()
    db.refresh(program)

    return _build_program_response(program, db)


@router.get("", response_model=List[ProgramResponse])
async def list_programs(
    request: Request,
    db: Session = Depends(get_db),
):
    user_ctx = get_user_context(request)
    user_id = user_ctx.get("user_id")

    query = db.query(Program).order_by(Program.created_at.desc())
    if user_id:
        query = query.filter((Program.user_id == user_id) | (Program.user_id.is_(None)))

    programs = query.limit(100).all()
    return [_build_program_response(p, db) for p in programs]


@router.get("/{program_id}", response_model=ProgramResponse)
async def get_program(
    program_id: str,
    db: Session = Depends(get_db),
):
    program = db.query(Program).filter_by(id=program_id).first()
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")

    return _build_program_response(program, db)


@router.put("/{program_id}/scope", response_model=ProgramResponse)
async def update_program_scope(
    program_id: str,
    scope_data: ScopeDefinitionSchema,
    db: Session = Depends(get_db),
):
    program = db.query(Program).filter_by(id=program_id).first()
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")

    now = datetime.now(timezone.utc)
    if program.scope:
        program.scope.in_scope_assets = json.dumps(scope_data.in_scope_assets)
        program.scope.out_of_scope_assets = json.dumps(scope_data.out_of_scope_assets)
        program.scope.allowed_ports = json.dumps(scope_data.allowed_ports)
        program.scope.excluded_ports = json.dumps(scope_data.excluded_ports)
        program.scope.allowed_schemes = json.dumps(scope_data.allowed_schemes)
        program.scope.excluded_paths = json.dumps(scope_data.excluded_paths)
        program.scope.scope_notes = scope_data.scope_notes
        program.scope.updated_at = now
    else:
        new_scope = ProgramScope(
            id=str(uuid.uuid4()),
            program_id=program_id,
            in_scope_assets=json.dumps(scope_data.in_scope_assets),
            out_of_scope_assets=json.dumps(scope_data.out_of_scope_assets),
            allowed_ports=json.dumps(scope_data.allowed_ports),
            excluded_ports=json.dumps(scope_data.excluded_ports),
            allowed_schemes=json.dumps(scope_data.allowed_schemes),
            excluded_paths=json.dumps(scope_data.excluded_paths),
            scope_notes=scope_data.scope_notes,
            created_at=now,
            updated_at=now,
        )
        db.add(new_scope)

    db.commit()
    db.refresh(program)

    return _build_program_response(program, db)


@router.post("/{program_id}/validate-target", response_model=ScopeValidationResponse)
async def validate_target_against_program(
    program_id: str,
    payload: ScopeValidationRequest,
    db: Session = Depends(get_db),
):
    program = db.query(Program).filter_by(id=program_id).first()
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")

    scope_schema = _parse_scope_model_to_schema(program.scope) or ScopeDefinitionSchema()
    validator = ScopeValidator(
        in_scope_assets=scope_schema.in_scope_assets,
        out_of_scope_assets=scope_schema.out_of_scope_assets,
        allowed_ports=scope_schema.allowed_ports if scope_schema.allowed_ports else None,
        excluded_ports=scope_schema.excluded_ports if scope_schema.excluded_ports else None,
        allowed_schemes=scope_schema.allowed_schemes,
        excluded_paths=scope_schema.excluded_paths,
        scope_notes=scope_schema.scope_notes,
    )

    if payload.port:
        decision = validator.is_port_in_scope(payload.target, payload.port)
    else:
        decision = validator.is_asset_in_scope(payload.target)

    return ScopeValidationResponse(
        allowed=decision.allowed,
        status=decision.status.value,
        reason=decision.reason,
        asset=decision.asset,
        matched_rule=decision.matched_rule,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Phase 16: Safe Bug-Bounty Program Import
# ──────────────────────────────────────────────────────────────────────────────

class ScopeAssetImportItem(BaseModel):
    asset_name: str
    asset_type: str = "DOMAIN"
    scope_type: str = "IN_SCOPE"
    severity: Optional[str] = None
    bounty_eligible: bool = False
    raw_scope_definition: str
    normalized_scope_definition: Optional[str] = None


class ImportProgramRequest(BaseModel):
    name: str
    description: Optional[str] = None
    platform: str = "hackerone"
    policy_url: Optional[str] = None
    policy_version: Optional[str] = None
    policy_updated_at: Optional[datetime] = None
    bounty_eligible: bool = False
    scope_assets: List[ScopeAssetImportItem] = []


@router.post("/import", status_code=201)
async def import_program(
    payload: ImportProgramRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Import a bug-bounty program with structured scope assets.

    CRITICAL INVARIANT:
    Importing wildcard definitions (e.g. *.xiaomi.com) ONLY creates scope rules.
    It does NOT create executable targets or launch scans.
    """
    from backend.models.database import BugBountyScopeAsset

    user_ctx = get_user_context(request)
    user_id = user_ctx.get("user_id")

    program_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    # 1. Create Program
    program = Program(
        id=program_id,
        name=payload.name,
        description=payload.description or f"Imported from {payload.platform}",
        user_id=user_id,
        platform=payload.platform,
        policy_url=payload.policy_url,
        policy_version=payload.policy_version,
        policy_updated_at=payload.policy_updated_at,
        bounty_eligible=payload.bounty_eligible,
        created_at=now,
    )
    db.add(program)

    # 2. Extract in-scope vs out-of-scope assets
    in_scope_list: List[str] = []
    out_of_scope_list: List[str] = []

    for item in payload.scope_assets:
        norm_def = item.normalized_scope_definition or item.raw_scope_definition.strip()
        asset_rec = BugBountyScopeAsset(
            id=str(uuid.uuid4()),
            program_id=program_id,
            asset_name=item.asset_name,
            asset_type=item.asset_type.upper(),
            scope_type=item.scope_type.upper(),
            severity=item.severity,
            bounty_eligible=item.bounty_eligible,
            raw_scope_definition=item.raw_scope_definition,
            normalized_scope_definition=norm_def,
            created_at=now,
        )
        db.add(asset_rec)

        if item.scope_type.upper() == "IN_SCOPE":
            in_scope_list.append(norm_def)
        else:
            out_of_scope_list.append(norm_def)

    # 3. Create ProgramScope
    scope = ProgramScope(
        id=str(uuid.uuid4()),
        program_id=program_id,
        in_scope_assets=json.dumps(in_scope_list),
        out_of_scope_assets=json.dumps(out_of_scope_list),
        allowed_ports=json.dumps([]),
        excluded_ports=json.dumps([]),
        allowed_schemes=json.dumps(["http", "https"]),
        excluded_paths=json.dumps([]),
        scope_notes=f"Imported from {payload.platform} with {len(payload.scope_assets)} scope assets",
        created_at=now,
        updated_at=now,
    )
    db.add(scope)

    db.commit()
    db.refresh(program)

    return {
        "success": True,
        "data": {
            "program_id": program.id,
            "name": program.name,
            "platform": program.platform,
            "policy_url": program.policy_url,
            "bounty_eligible": program.bounty_eligible,
            "scope_assets_count": len(payload.scope_assets),
            "in_scope_count": len(in_scope_list),
            "out_of_scope_count": len(out_of_scope_list),
            "executable_targets_created": 0,  # Explicit proof that no executable targets are created
        },
    }

