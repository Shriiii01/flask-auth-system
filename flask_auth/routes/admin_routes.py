from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import List, Optional
from ..database import get_db
from ..models import User, Role, ActivityLog
from ..utils import role_required, admin_required
from ..utils.jwt import get_current_user
from ..utils.logger import log_action
from ..schemas import RoleCreate, RoleAssign, UserUpdate, MessageResponse
from ..extensions import logger
from datetime import datetime
import traceback

router = APIRouter()

@router.post(
    "/roles",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create new role",
    description="Creates a new role in the system"
)
async def create_role(
    role_data: RoleCreate,
    current_user: User = Depends(role_required("admin")),
    db: Session = Depends(get_db)
):
    try:
        if db.query(Role).filter(Role.name == role_data.name).first():
            raise HTTPException(status_code=400, detail="Role already exists")

        new_role = Role(name=role_data.name, description=role_data.description)
        db.add(new_role)
        db.commit()
        db.refresh(new_role)
        
        log_action(db, actor_id=current_user.id, action=f"Created role '{role_data.name}'")
        logger.info(f"Role created successfully: {role_data.name}")
        
        return {"message": f"Role '{role_data.name}' created successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Role creation failed: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Failed to create role")

@router.get(
    "/roles",
    summary="List all roles",
    description="Returns a list of all roles in the system"
)
async def list_roles(
    current_user: User = Depends(role_required("admin")),
    db: Session = Depends(get_db)
):
    try:
        roles = db.query(Role).all()
        return [{
            "id": r.id,
            "name": r.name,
            "description": r.description
        } for r in roles]
    except Exception as e:
        logger.error(f"Failed to list roles: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Failed to retrieve roles")

@router.post(
    "/users/{user_id}/roles",
    response_model=MessageResponse,
    summary="Assign role to user",
    description="Assigns a role to a specific user"
)
async def assign_role(
    user_id: int,
    role_data: RoleAssign,
    current_user: User = Depends(role_required("admin")),
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        role = db.query(Role).filter(Role.name == role_data.role).first()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
            
        if role in user.roles:
            raise HTTPException(status_code=400, detail="User already has this role")
            
        user.roles.append(role)
        db.commit()
        
        log_action(db, actor_id=current_user.id, action=f"Assigned role '{role_data.role}' to user {user.username}")
        logger.info(f"Role '{role_data.role}' assigned to user {user.username}")
        
        return {"message": f"Role '{role_data.role}' assigned to user successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Role assignment failed: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Failed to assign role")

@router.delete(
    "/users/{user_id}/roles",
    response_model=MessageResponse,
    summary="Remove role from user",
    description="Removes a role from a specific user"
)
async def remove_role(
    user_id: int,
    role_data: RoleAssign,
    current_user: User = Depends(role_required("admin")),
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        role = db.query(Role).filter(Role.name == role_data.role).first()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
            
        if role not in user.roles:
            raise HTTPException(status_code=400, detail="User does not have this role")
            
        user.roles.remove(role)
        db.commit()
        
        log_action(db, actor_id=current_user.id, action=f"Removed role '{role_data.role}' from user {user.username}")
        logger.info(f"Role '{role_data.role}' removed from user {user.username}")
        
        return {"message": f"Role '{role_data.role}' removed from user successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Role removal failed: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Failed to remove role")

@router.delete(
    "/roles/{role_id}",
    response_model=MessageResponse,
    summary="Delete role",
    description="Deletes a role from the system"
)
async def delete_role(
    role_id: int,
    current_user: User = Depends(role_required("admin")),
    db: Session = Depends(get_db)
):
    try:
        role = db.query(Role).filter(Role.id == role_id).first()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
            
        if role.name == "admin":
            raise HTTPException(status_code=400, detail="Cannot delete admin role")
            
        db.delete(role)
        db.commit()
        
        log_action(db, actor_id=current_user.id, action=f"Deleted role '{role.name}'")
        logger.info(f"Role '{role.name}' deleted successfully")
        
        return {"message": f"Role '{role.name}' deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Role deletion failed: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Failed to delete role")

@router.get(
    "/activity-logs",
    summary="Get activity logs",
    description="Returns a list of activity logs"
)
async def get_logs(
    limit: int = Query(50, ge=1, le=1000),
    current_user: User = Depends(role_required("admin")),
    db: Session = Depends(get_db)
):
    try:
        logs = db.query(ActivityLog).order_by(ActivityLog.timestamp.desc()).limit(limit).all()
        
        return [{
            "id": log.id,
            "actor_id": log.actor_id,
            "action": log.action,
            "target": log.target,
            "timestamp": log.timestamp.isoformat()
        } for log in logs]
        
    except Exception as e:
        logger.error(f"Failed to retrieve activity logs: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Failed to retrieve activity logs")

@router.get(
    "/users",
    summary="Get all users",
    description="Retrieves a list of all users in the system"
)
async def get_all_users(
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    users = db.query(User).all()
    return [{
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "roles": [role.name for role in user.roles],
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None
    } for user in users]

@router.put(
    "/users/{user_id}",
    summary="Update user",
    description="Update user details including username, email, active status, and roles"
)
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user_data.username is not None:
        if db.query(User).filter(User.username == user_data.username, User.id != user_id).first():
            raise HTTPException(status_code=400, detail="Username already taken")
        user.username = user_data.username
    
    if user_data.email is not None:
        if db.query(User).filter(User.email == user_data.email, User.id != user_id).first():
            raise HTTPException(status_code=400, detail="Email already in use")
        user.email = user_data.email
    
    if user_data.is_active is not None:
        user.is_active = user_data.is_active
    
    if user_data.roles is not None:
        user.roles = [db.query(Role).filter(Role.name == role_name).first() for role_name in user_data.roles]
    
    user.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(user)
    
    return {
        "message": "User updated successfully",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "roles": [role.name for role in user.roles],
            "is_active": user.is_active
        }
    }

@router.delete(
    "/users/{user_id}",
    response_model=MessageResponse,
    summary="Delete user",
    description="Delete a user from the system"
)
async def delete_user(
    user_id: int,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.delete(user)
    db.commit()
    
    return {"message": "User deleted successfully"}
