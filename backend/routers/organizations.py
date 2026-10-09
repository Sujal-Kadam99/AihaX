"""Team workspace and role-based membership API."""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.core.entitlements import EntitlementManager, get_user_tier, require_team
from backend.models.database import (
    EntitlementCache,
    Organization,
    OrganizationMember,
    User,
    get_db,
)
from backend.core.auth import get_current_user

router = APIRouter(prefix="/api/organizations", tags=["Team Workspaces"])

WorkspaceRole = Literal["owner", "admin", "member", "viewer"]
AssignableRole = Literal["admin", "member", "viewer"]


class CreateOrganizationPayload(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)


class AddOrganizationMemberPayload(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    role: AssignableRole = "member"


class ChangeOrganizationMemberRolePayload(BaseModel):
    role: AssignableRole


def _membership_or_404(db: Session, organization_id: str, user_id: str) -> tuple[Organization, OrganizationMember]:
    member = (
        db.query(OrganizationMember)
        .filter_by(organization_id=organization_id, user_id=user_id)
        .first()
    )
    if not member:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return member.organization, member


def _require_manager(member: OrganizationMember) -> None:
    if member.role not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Workspace administrator role required")


def _seat_limit(db: Session, organization: Organization) -> int | None:
    """Read the owner's signed plan claim for seat enforcement."""
    cache = db.query(EntitlementCache).filter_by(user_id=organization.created_by_user_id).first()
    if not cache:
        raise HTTPException(status_code=403, detail="Workspace owner's paid entitlement is unavailable")
    try:
        claims = EntitlementManager.verify_entitlement_token(
            cache.entitlement_jwt,
            expected_user_id=organization.created_by_user_id,
        )
    except HTTPException as exc:
        raise HTTPException(status_code=403, detail="Workspace owner's paid entitlement is invalid or expired") from exc

    tier = claims.get("tier")
    plan = str(claims.get("plan", "")).casefold()
    if tier not in {"team", "founder"}:
        raise HTTPException(status_code=403, detail="A Team plan is required to manage workspace seats")
    if tier == "founder" or any(value in plan for value in ("agency", "enterprise")):
        return None
    return 5


def _organization_summary(organization: Organization, role: str, member_count: int) -> dict:
    return {
        "id": organization.id,
        "name": organization.name,
        "role": role,
        "member_count": member_count,
        "created_at": organization.created_at.isoformat(),
    }


@router.post("", status_code=status.HTTP_201_CREATED)
def create_organization(
    payload: CreateOrganizationPayload,
    current_user: User = Depends(get_current_user),
    _team_tier: str = Depends(require_team),
    db: Session = Depends(get_db),
):
    organization = Organization(
        id=str(uuid.uuid4()),
        name=payload.name.strip(),
        created_by_user_id=current_user.id,
    )
    db.add(organization)
    db.flush()
    db.add(
        OrganizationMember(
            id=str(uuid.uuid4()),
            organization_id=organization.id,
            user_id=current_user.id,
            role="owner",
            invited_by_user_id=current_user.id,
        )
    )
    db.commit()
    db.refresh(organization)
    return {"success": True, "data": _organization_summary(organization, "owner", 1)}


@router.get("")
def list_organizations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    memberships = (
        db.query(OrganizationMember)
        .filter_by(user_id=current_user.id)
        .order_by(OrganizationMember.created_at.asc())
        .all()
    )
    data = []
    for membership in memberships:
        count = db.query(OrganizationMember).filter_by(organization_id=membership.organization_id).count()
        data.append(_organization_summary(membership.organization, membership.role, count))
    return {"success": True, "data": data}


@router.get("/{organization_id}")
def get_organization(
    organization_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    organization, membership = _membership_or_404(db, organization_id, current_user.id)
    count = db.query(OrganizationMember).filter_by(organization_id=organization_id).count()
    return {"success": True, "data": _organization_summary(organization, membership.role, count)}


@router.get("/{organization_id}/members")
def list_organization_members(
    organization_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _membership_or_404(db, organization_id, current_user.id)
    members = (
        db.query(OrganizationMember)
        .filter_by(organization_id=organization_id)
        .order_by(OrganizationMember.created_at.asc())
        .all()
    )
    return {
        "success": True,
        "data": [
            {
                "user_id": member.user_id,
                "email": member.user.email,
                "name": member.user.name,
                "role": member.role,
                "joined_at": member.created_at.isoformat(),
            }
            for member in members
        ],
    }


@router.post("/{organization_id}/members", status_code=status.HTTP_201_CREATED)
def add_organization_member(
    organization_id: str,
    payload: AddOrganizationMemberPayload,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    organization, actor_membership = _membership_or_404(db, organization_id, current_user.id)
    _require_manager(actor_membership)
    if actor_membership.role == "admin" and payload.role == "admin":
        raise HTTPException(status_code=403, detail="Only the workspace owner can appoint administrators")

    email = payload.email.strip().casefold()
    if "@" not in email or any(character.isspace() for character in email):
        raise HTTPException(status_code=422, detail="Enter a valid account email address")
    invited_user = db.query(User).filter(User.email.ilike(email)).first()
    if not invited_user or invited_user.account_status != "active":
        raise HTTPException(status_code=404, detail="An active AihaX account with that email was not found")
    existing = db.query(OrganizationMember).filter_by(
        organization_id=organization_id, user_id=invited_user.id
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="User is already a workspace member")

    limit = _seat_limit(db, organization)
    member_count = db.query(OrganizationMember).filter_by(organization_id=organization_id).count()
    if limit is not None and member_count >= limit:
        raise HTTPException(status_code=409, detail=f"This plan supports up to {limit} workspace members")

    membership = OrganizationMember(
        id=str(uuid.uuid4()),
        organization_id=organization_id,
        user_id=invited_user.id,
        role=payload.role,
        invited_by_user_id=current_user.id,
    )
    db.add(membership)
    db.commit()
    db.refresh(membership)
    return {
        "success": True,
        "data": {
            "user_id": invited_user.id,
            "email": invited_user.email,
            "role": membership.role,
            "joined_at": membership.created_at.isoformat(),
        },
    }


@router.patch("/{organization_id}/members/{user_id}")
def change_organization_member_role(
    organization_id: str,
    user_id: str,
    payload: ChangeOrganizationMemberRolePayload,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _, actor_membership = _membership_or_404(db, organization_id, current_user.id)
    _require_manager(actor_membership)
    target = db.query(OrganizationMember).filter_by(
        organization_id=organization_id, user_id=user_id
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Workspace member not found")
    if target.role == "owner":
        raise HTTPException(status_code=409, detail="Workspace ownership cannot be reassigned through role editing")
    if actor_membership.role == "admin" and target.role == "admin":
        raise HTTPException(status_code=403, detail="Only the workspace owner can change administrators")
    if actor_membership.role == "admin" and payload.role == "admin":
        raise HTTPException(status_code=403, detail="Only the workspace owner can appoint administrators")

    target.role = payload.role
    db.commit()
    return {"success": True, "data": {"user_id": target.user_id, "role": target.role}}


@router.delete("/{organization_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_organization_member(
    organization_id: str,
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _, actor_membership = _membership_or_404(db, organization_id, current_user.id)
    _require_manager(actor_membership)
    target = db.query(OrganizationMember).filter_by(
        organization_id=organization_id, user_id=user_id
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Workspace member not found")
    if target.role == "owner":
        raise HTTPException(status_code=409, detail="The workspace owner cannot be removed")
    if actor_membership.role == "admin" and target.role == "admin":
        raise HTTPException(status_code=403, detail="Only the workspace owner can remove administrators")
    db.delete(target)
    db.commit()
