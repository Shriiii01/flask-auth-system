from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from ..database import get_db
from ..models import User
from ..utils.jwt import create_access_token, create_refresh_token, verify_token, get_current_user
from ..extensions import limiter, logger
from ..schemas import UserRegister, UserLogin, TokenResponse, RefreshTokenResponse, MessageResponse, ErrorResponse
from config import Config
import secrets
import traceback
from datetime import datetime

router = APIRouter()
security = HTTPBearer()

@router.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Creates a new user account and sends a verification email",
    responses={
        201: {"description": "User registered successfully"},
        400: {"description": "Bad request", "model": ErrorResponse}
    }
)
@limiter.limit("3 per minute")
async def register(
    request: Request,
    user_data: UserRegister,
    db: Session = Depends(get_db)
):
    try:
        logger.debug(f"Registration attempt for username: {user_data.username}, email: {user_data.email}")

        if db.query(User).filter(User.email == user_data.email).first():
            logger.warning(f"Registration attempt with existing email: {user_data.email}")
            raise HTTPException(status_code=400, detail="Email already registered")
            
        if db.query(User).filter(User.username == user_data.username).first():
            logger.warning(f"Registration attempt with existing username: {user_data.username}")
            raise HTTPException(status_code=400, detail="Username already taken")

        email_token = secrets.token_urlsafe(32)
        new_user = User(
            username=user_data.username,
            email=user_data.email,
            email_verification_token=email_token,
            is_active=True,
            is_verified=False
        )
        new_user.set_password(user_data.password)

        try:
            db.add(new_user)
            db.commit()
            db.refresh(new_user)
            logger.info(f"Successfully registered new user: {user_data.username}")
            
            verification_link = f"{Config.BASE_URL}/auth/verify-email/{email_token}"
            
            return {
                "message": "User registered successfully",
                "verification_link": verification_link
            }
            
        except Exception as e:
            db.rollback()
            logger.error(f"Database error during registration: {str(e)}\n{traceback.format_exc()}")
            raise HTTPException(status_code=500, detail="Database error occurred")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration failed: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Registration failed")

@router.get(
    "/verify-email/{token}",
    response_model=MessageResponse,
    summary="Verify email address",
    description="Verifies a user's email address using the token sent during registration",
    responses={
        200: {"description": "Email verified successfully"},
        400: {"description": "Invalid or expired token", "model": ErrorResponse}
    }
)
async def verify_email(token: str, db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.email_verification_token == token).first()
        if not user:
            raise HTTPException(status_code=400, detail="Invalid verification token")
            
        user.is_verified = True
        user.email_verification_token = None
        db.commit()
        logger.info(f"Email verified successfully for user: {user.username}")
        
        return {"message": "Email verified successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email verification failed: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Email verification failed")

@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login user",
    description="Authenticates a user and returns JWT tokens",
    responses={
        200: {"description": "Login successful"},
        400: {"description": "Bad request", "model": ErrorResponse},
        401: {"description": "Invalid credentials", "model": ErrorResponse}
    }
)
@limiter.limit("5 per minute")
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

        if not user.is_verified:
            raise HTTPException(status_code=401, detail="Email not verified")

        access_token = create_access_token(data={"sub": user.id})
        refresh_token = create_refresh_token(data={"sub": user.id})
        
        logger.info(f"User logged in successfully: {user.username}")

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "roles": [role.name for role in user.roles]
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
    summary="Logout user",
    description="Invalidates the current JWT token",
    responses={
        200: {"description": "Logged out successfully"},
        401: {"description": "Invalid token", "model": ErrorResponse}
    }
)
async def logout(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        current_user.token_revoked_at = datetime.utcnow()
        db.commit()
        logger.info(f"User logged out successfully: {current_user.username}")
        return {"message": "Successfully logged out"}
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Logout failed")

@router.post(
    "/refresh",
    response_model=RefreshTokenResponse,
    summary="Refresh access token",
    description="Get a new access token using a refresh token",
    responses={
        200: {"description": "New access token generated"},
        401: {"description": "Invalid refresh token", "model": ErrorResponse}
    }
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
        logger.info(f"Access token refreshed for user ID: {user_id}")
        return {"access_token": new_access_token}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Token refresh failed")
