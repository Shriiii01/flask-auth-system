from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from config import Config
from .extensions import limiter, RateLimitExceeded
from .oauth import configure_oauth

def create_app():
    app = FastAPI(
        title="Authentication API",
        description="Full-featured FastAPI Auth System with JWT, OAuth, and Role-based Access Control",
        version="1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json"
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Rate limiting exception handler
    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request, exc):
        response = JSONResponse(
            {"error": "Rate limit exceeded"},
            status_code=429
        )
        response = limiter._inject_headers(
            response,
            request.state.view_args.get("rate_limit", None)
        )
        return response

    # Initialize rate limiter
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

    # Include routers
    from .routes.auth import router as auth_router
    from .routes.main import router as main_router
    from .routes.admin_routes import router as admin_router

    app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
    app.include_router(main_router, tags=["Main"])
    app.include_router(admin_router, prefix="/admin", tags=["Admin"])

    # Configure OAuth
    configure_oauth(app)

    return app