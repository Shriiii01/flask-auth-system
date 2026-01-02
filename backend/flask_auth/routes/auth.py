from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from slowapi import Limiter
from ..database import get_db
from ..models import User
from ..utils.jwt import create_access_token, create_refresh_token, verify_token, get_current_user
from ..extensions import limiter, logger
from ..schemas import UserRegister, UserLogin, TokenResponse, RefreshTokenResponse, MessageResponse
from ..oauth import get_google_oauth_client, get_github_oauth_client
from config import Config
import traceback
import httpx
from urllib.parse import urlencode

router = APIRouter()
security = HTTPBearer(auto_error=False)

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
@limiter.limit("10 per minute")
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
        
        return {
            "message": "User created successfully",
            "user_id": new_user.id
        }
            
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
        if not user:
            raise HTTPException(status_code=401, detail="Invalid email or password")
        
        if not user.check_password(user_data.password):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")

        access_token = create_access_token(data={"sub": user.id})
        refresh_token = create_refresh_token(data={"sub": user.id})
        
        logger.info(f"User logged in successfully: {user.username} (ID: {user.id})")

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "created_at": user.created_at.isoformat() if user.created_at else None
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
async def logout(current_user: User = Depends(get_current_user)):
    logger.info(f"User logged out: {current_user.username}")
    return {"message": "Successfully logged out"}

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

@router.get("/google")
async def google_login():
    """Initiate Google OAuth login"""
    if not Config.GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Google OAuth not configured")
    
    client = get_google_oauth_client()
    redirect_uri = f"{Config.BASE_URL}/auth/google/callback"
    
    authorization_url, state = client.create_authorization_url(
        "https://accounts.google.com/o/oauth2/v2/auth",
        redirect_uri=redirect_uri
    )
    
    return RedirectResponse(url=authorization_url)

@router.get("/google/callback")
async def google_callback(request: Request, code: str = None, db: Session = Depends(get_db)):
    """Handle Google OAuth callback"""
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not provided")
    
    try:
        client = get_google_oauth_client()
        redirect_uri = f"{Config.BASE_URL}/auth/google/callback"
        
        token = await client.fetch_token(
            "https://oauth2.googleapis.com/token",
            code=code,
            redirect_uri=redirect_uri
        )
        
        # Get user info from Google
        async with httpx.AsyncClient() as http_client:
            response = await http_client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {token['access_token']}"}
            )
            google_user = response.json()
        
        email = google_user.get("email")
        name = google_user.get("name", "")
        username = email.split("@")[0] if email else name.lower().replace(" ", "")
        
        # Find or create user
        user = db.query(User).filter(User.email == email).first()
        if not user:
            # Create new user
            user = User(
                username=username,
                email=email,
                is_active=True
            )
            # Set a random password (OAuth users don't need password)
            user.set_password("oauth_user_no_password")
            db.add(user)
            db.commit()
            db.refresh(user)
            logger.info(f"New user created via Google OAuth: {email}")
        
        # Generate tokens
        access_token = create_access_token(data={"sub": user.id})
        refresh_token = create_refresh_token(data={"sub": user.id})
        
        # Redirect to frontend with tokens
        frontend_url = f"{Config.BASE_URL}/?token={access_token}&refresh_token={refresh_token}"
        return RedirectResponse(url=frontend_url)
        
    except Exception as e:
        logger.error(f"Google OAuth failed: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Google OAuth authentication failed")

@router.get("/github")
async def github_login():
    """Initiate GitHub OAuth login"""
    if not Config.GITHUB_CLIENT_ID:
        raise HTTPException(status_code=500, detail="GitHub OAuth not configured")
    
    client = get_github_oauth_client()
    redirect_uri = f"{Config.BASE_URL}/auth/github/callback"
    
    authorization_url, state = client.create_authorization_url(
        "https://github.com/login/oauth/authorize",
        redirect_uri=redirect_uri
    )
    
    return RedirectResponse(url=authorization_url)

@router.get("/github/callback")
async def github_callback(request: Request, code: str = None, db: Session = Depends(get_db)):
    """Handle GitHub OAuth callback"""
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not provided")
    
    try:
        client = get_github_oauth_client()
        redirect_uri = f"{Config.BASE_URL}/auth/github/callback"
        
        token = await client.fetch_token(
            "https://github.com/login/oauth/access_token",
            code=code,
            redirect_uri=redirect_uri
        )
        
        # Get user info from GitHub
        async with httpx.AsyncClient() as http_client:
            response = await http_client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {token['access_token']}"}
            )
            github_user = response.json()
            
            # Get email (might need separate call)
            email_response = await http_client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {token['access_token']}"}
            )
            emails = email_response.json()
            email = next((e["email"] for e in emails if e["primary"]), emails[0]["email"] if emails else None)
        
        username = github_user.get("login", email.split("@")[0] if email else "github_user")
        name = github_user.get("name", username)
        
        # Find or create user
        user = db.query(User).filter(User.email == email).first()
        if not user:
            # Create new user
            user = User(
                username=username,
                email=email,
                is_active=True
            )
            # Set a random password (OAuth users don't need password)
            user.set_password("oauth_user_no_password")
            db.add(user)
            db.commit()
            db.refresh(user)
            logger.info(f"New user created via GitHub OAuth: {email}")
        
        # Generate tokens
        access_token = create_access_token(data={"sub": user.id})
        refresh_token = create_refresh_token(data={"sub": user.id})
        
        # Redirect to frontend with tokens
        frontend_url = f"{Config.BASE_URL}/?token={access_token}&refresh_token={refresh_token}"
        return RedirectResponse(url=frontend_url)
        
    except Exception as e:
        logger.error(f"GitHub OAuth failed: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="GitHub OAuth authentication failed")
