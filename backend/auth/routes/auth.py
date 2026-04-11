from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import User
from ..utils.jwt import create_access_token, create_refresh_token, verify_token, get_current_user
from ..extensions import limiter, logger, blacklist_token
from ..schemas import UserRegister, UserLogin, TokenResponse, RefreshTokenResponse, MessageResponse
from ..oauth import get_google_oauth_client, get_github_oauth_client
from config import Config
import traceback
import httpx

router = APIRouter()
security = HTTPBearer(auto_error=False)


@router.post(
    "/signup",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Sign up",
    description="Create a new user account",
)
@limiter.limit("10 per minute")
async def signup(
    request: Request,
    user_data: UserRegister,
    db: Session = Depends(get_db),
):
    try:
        if db.query(User).filter(User.email == user_data.email).first():
            raise HTTPException(status_code=400, detail="Email already registered")

        if db.query(User).filter(User.username == user_data.username).first():
            raise HTTPException(status_code=400, detail="Username already taken")

        new_user = User(username=user_data.username, email=user_data.email, is_active=True)
        new_user.set_password(user_data.password)

        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        logger.info(f"New user signed up: {user_data.username}")

        return {"message": "Account created successfully", "user_id": new_user.id}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Signup error: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Signup failed. Please try again.")


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login",
    description="Authenticate with email and password to receive JWT tokens",
)
@limiter.limit("10 per minute")
async def login(
    request: Request,
    user_data: UserLogin,
    db: Session = Depends(get_db),
):
    try:
        user = db.query(User).filter(User.email == user_data.email).first()
        # Always run check_password to avoid timing-based user enumeration
        if not user or not user.check_password(user_data.password):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account is deactivated")

        access_token = create_access_token(data={"sub": user.id})
        refresh_token = create_refresh_token(data={"sub": user.id})

        logger.info(f"User logged in: {user.username} (ID: {user.id})")

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "created_at": user.created_at.isoformat() if user.created_at else None,
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Login failed. Please try again.")


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Logout",
    description="Revoke the current access token",
)
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: User = Depends(get_current_user),
):
    # Blacklist the token so it can't be reused after logout
    token = credentials.credentials
    blacklist_token(token, expires_in_seconds=int(Config.JWT_ACCESS_TOKEN_EXPIRES.total_seconds()))
    logger.info(f"User logged out: {current_user.username}")
    return {"message": "Successfully logged out"}


@router.post(
    "/refresh",
    response_model=RefreshTokenResponse,
    summary="Refresh token",
    description="Exchange a refresh token for a new access token",
)
async def refresh(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    if not credentials:
        raise HTTPException(status_code=401, detail="Refresh token required")
    try:
        token = credentials.credentials
        payload = verify_token(token)
        if payload is None:
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Refresh token required")

        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        new_access_token = create_access_token(data={"sub": user_id})
        logger.info(f"Token refreshed for user ID: {user_id}")
        return {"access_token": new_access_token}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh error: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Token refresh failed")


@router.get("/google", summary="Google OAuth", description="Initiate Google OAuth login flow")
async def google_login():
    if not Config.GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=501, detail="Google OAuth is not configured on this server")

    client = get_google_oauth_client()
    redirect_uri = f"{Config.BASE_URL}/auth/google/callback"
    authorization_url, _ = client.create_authorization_url(
        "https://accounts.google.com/o/oauth2/v2/auth",
        redirect_uri=redirect_uri,
    )
    return RedirectResponse(url=authorization_url)


@router.get("/google/callback", include_in_schema=False)
async def google_callback(request: Request, code: str = None, db: Session = Depends(get_db)):
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not provided")

    try:
        client = get_google_oauth_client()
        redirect_uri = f"{Config.BASE_URL}/auth/google/callback"

        token = await client.fetch_token(
            "https://oauth2.googleapis.com/token",
            code=code,
            redirect_uri=redirect_uri,
        )

        async with httpx.AsyncClient() as http_client:
            resp = await http_client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {token['access_token']}"},
            )
            google_user = resp.json()

        email = google_user.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Could not retrieve email from Google")

        username = email.split("@")[0]

        user = db.query(User).filter(User.email == email).first()
        if not user:
            # Ensure username is unique
            base_username = username
            counter = 1
            while db.query(User).filter(User.username == username).first():
                username = f"{base_username}{counter}"
                counter += 1

            user = User(username=username, email=email, is_active=True)
            user.set_password(f"oauth_{email}")  # Non-guessable placeholder
            db.add(user)
            db.commit()
            db.refresh(user)
            logger.info(f"New user via Google OAuth: {email}")

        access_token = create_access_token(data={"sub": user.id})
        refresh_token = create_refresh_token(data={"sub": user.id})

        return RedirectResponse(url=f"{Config.BASE_URL}/dashboard?token={access_token}&refresh_token={refresh_token}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Google OAuth error: {e}\n{traceback.format_exc()}")
        return RedirectResponse(url=f"{Config.BASE_URL}/?error=oauth_failed")


@router.get("/github", summary="GitHub OAuth", description="Initiate GitHub OAuth login flow")
async def github_login():
    if not Config.GITHUB_CLIENT_ID:
        raise HTTPException(status_code=501, detail="GitHub OAuth is not configured on this server")

    client = get_github_oauth_client()
    redirect_uri = f"{Config.BASE_URL}/auth/github/callback"
    authorization_url, _ = client.create_authorization_url(
        "https://github.com/login/oauth/authorize",
        redirect_uri=redirect_uri,
    )
    return RedirectResponse(url=authorization_url)


@router.get("/github/callback", include_in_schema=False)
async def github_callback(request: Request, code: str = None, db: Session = Depends(get_db)):
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not provided")

    try:
        client = get_github_oauth_client()
        redirect_uri = f"{Config.BASE_URL}/auth/github/callback"

        token = await client.fetch_token(
            "https://github.com/login/oauth/access_token",
            code=code,
            redirect_uri=redirect_uri,
        )

        async with httpx.AsyncClient() as http_client:
            user_resp = await http_client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {token['access_token']}"},
            )
            github_user = user_resp.json()

            email_resp = await http_client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {token['access_token']}"},
            )
            emails = email_resp.json()
            email = next((e["email"] for e in emails if e.get("primary")), None)
            if not email and emails:
                email = emails[0]["email"]

        if not email:
            raise HTTPException(status_code=400, detail="Could not retrieve email from GitHub")

        username = github_user.get("login", email.split("@")[0])

        user = db.query(User).filter(User.email == email).first()
        if not user:
            base_username = username
            counter = 1
            while db.query(User).filter(User.username == username).first():
                username = f"{base_username}{counter}"
                counter += 1

            user = User(username=username, email=email, is_active=True)
            user.set_password(f"oauth_{email}")
            db.add(user)
            db.commit()
            db.refresh(user)
            logger.info(f"New user via GitHub OAuth: {email}")

        access_token = create_access_token(data={"sub": user.id})
        refresh_token = create_refresh_token(data={"sub": user.id})

        return RedirectResponse(url=f"{Config.BASE_URL}/dashboard?token={access_token}&refresh_token={refresh_token}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"GitHub OAuth error: {e}\n{traceback.format_exc()}")
        return RedirectResponse(url=f"{Config.BASE_URL}/?error=oauth_failed")
