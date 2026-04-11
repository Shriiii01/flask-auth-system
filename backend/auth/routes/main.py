from fastapi import APIRouter, Depends
from ..utils.jwt import get_current_active_user
from ..models import User

router = APIRouter()


@router.get(
    "/api/me",
    summary="Get current user",
    description="Returns profile information for the authenticated user",
)
async def get_me(current_user: User = Depends(get_current_active_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "is_active": current_user.is_active,
        "created_at": current_user.created_at.isoformat() if current_user.created_at else None,
    }


@router.get("/api/health", include_in_schema=False)
async def health():
    return {"status": "ok"}
