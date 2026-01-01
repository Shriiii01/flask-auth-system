from fastapi import Depends, HTTPException, status
from ..models import User
from .jwt import get_current_user

def role_required(required_role: str):
    async def role_checker(current_user: User = Depends(get_current_user)):
        if not any(role.name == required_role for role in current_user.roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: {required_role} role required"
            )
        return current_user
    return role_checker

def admin_required(current_user: User = Depends(get_current_user)):
    if not any(role.name == "admin" for role in current_user.roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user 