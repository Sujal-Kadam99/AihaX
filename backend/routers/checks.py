"""Router for Check Registry endpoints."""

from typing import List

from fastapi import APIRouter, Depends

from backend.core.auth import get_current_user
from backend.core.check_registry import CheckContract, registry
from backend.models.database import User

router = APIRouter(prefix="/api/checks", tags=["checks"])


@router.get("", response_model=List[CheckContract])
async def list_checks(current_user: User = Depends(get_current_user)):
    """List all registered security checks."""
    return registry.list_checks()
