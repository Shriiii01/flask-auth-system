from fastapi import APIRouter, Depends
from ..utils.jwt import get_current_active_user
from ..models import User

router = APIRouter()

@router.get(
    "/",
    summary="Home endpoint",
    description="Returns a welcome message. Requires authentication."
)
async def home(current_user: User = Depends(get_current_active_user)):
    return {
        "message": "Welcome to the Authentication System!",
        "user": {
            "id": current_user.id,
            "username": current_user.username,
            "email": current_user.email,
            "created_at": current_user.created_at.isoformat() if current_user.created_at else None
        }
    } 