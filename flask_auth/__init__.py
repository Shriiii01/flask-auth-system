from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from config import Config
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from .extensions import limiter

def create_app():
    app = FastAPI(
        title="Simple Auth API",
        description="Simple authentication system with signup, login, and JWT tokens",
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

    # Initialize rate limiter
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Include routers
    from .routes.auth import router as auth_router
    from .routes.main import router as main_router

    app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
    app.include_router(main_router, tags=["Main"])

    # Serve static files
    static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
    if os.path.exists(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")
    
    # Serve index.html at root
    @app.get("/", include_in_schema=False)
    async def read_root():
        index_path = os.path.join(static_dir, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"message": "API is running. Visit /docs for API documentation."}

    return app