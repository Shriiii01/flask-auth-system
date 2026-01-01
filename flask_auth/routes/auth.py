from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from ..database import get_db
from ..models import User
from ..utils.jwt import create_access_token, create_refresh_token, verify_token, get_current_user
from ..extensions import limiter, logger
from ..schemas import UserRegister, UserLogin, TokenResponse, RefreshTokenResponse, MessageResponse
from config import Config
import traceback
from datetime import datetime

router = APIRouter()
security = HTTPBearer()

@router.post(
    "/signup",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Sign up",
    description="Create a new user account",
    responses={
        201: {"description": "User created successfully"},
        400: {"description": "Bad request"}
    }
)
@limiter.limit("5 per minute")
async def signup(
    request: Request,
    user_data: UserRegister,
    db: Session = Depends(get_db)
):
    try:
        if db.query(User).filter(User.email == user_data.email).first():
            raise HTTPException(status_code=400, detail="Email already registered")
            
        if db.query(User).filter(User.username == user_data.username).first():
            raise HTTPException(status_code=400, detail="Username already taken")

        new_user = User(
            username=user_data.username,
            email=user_data.email,
            is_active=True
        )
        new_user.set_password(user_data.password)

        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        logger.info(f"User signed up: {user_data.username}")
        
        return {"message": "User created successfully"}
            
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Signup failed: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Signup failed")

@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login",
    description="Authenticate and get access tokens",
    responses={
        200: {"description": "Login successful"},
        401: {"description": "Invalid credentials"}
    }
)
@limiter.limit("10 per minute")
async def login(
    request: Request,
    user_data: UserLogin,
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(User.email == user_data.email).first()
        if not user or not user.check_password(user_data.password):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        if not user.is_active:
            raise HTTPException(status_code=401, detail="Account is deactivated")

        access_token = create_access_token(data={"sub": user.id})
        refresh_token = create_refresh_token(data={"sub": user.id})
        
        logger.info(f"User logged in: {user.username}")

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login failed: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Login failed")

@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Logout",
    description="Logout current user"
)
async def logout(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        current_user.token_revoked_at = datetime.utcnow()
        db.commit()
        logger.info(f"User logged out: {current_user.username}")
        return {"message": "Successfully logged out"}
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Logout failed")

@router.post(
    "/refresh",
    response_model=RefreshTokenResponse,
    summary="Refresh token",
    description="Get a new access token using refresh token"
)
async def refresh(
    credentials: HTTPBearer = Depends(security),
    db: Session = Depends(get_db)
):
    try:
        token = credentials.credentials
        payload = verify_token(token)
        if payload is None:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        
        new_access_token = create_access_token(data={"sub": user_id})
        logger.info(f"Token refreshed for user ID: {user_id}")
        return {"access_token": new_access_token}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Token refresh failed")
