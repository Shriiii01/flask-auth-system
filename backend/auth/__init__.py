import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from slowapi.middleware import SlowAPIMiddleware
from .extensions import limiter
from .database import Base, engine
from .models import User  # noqa: F401 — register models with Base.metadata

# Resolve path to the static directory (project_root/static)
_backend_dir = os.path.dirname(os.path.dirname(__file__))
_project_root = os.path.dirname(_backend_dir)
STATIC_DIR = os.path.join(_project_root, "static")


@asynccontextmanager
async def _lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="FastAPI Auth System",
        description=(
            "A production-ready authentication API with JWT tokens, "
            "OAuth (Google & GitHub), and rate limiting."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=_lifespan,
    )

    # Allow all origins in development; restrict in production via environment config
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Rate limiter (SlowAPIMiddleware must be registered for @limiter.limit on routes)
    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Routers
    from .routes.auth import router as auth_router
    from .routes.main import router as main_router

    app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
    app.include_router(main_router, tags=["User"])

    # Static files
    if os.path.exists(STATIC_DIR):
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_index():
        index_path = os.path.join(STATIC_DIR, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return JSONResponse({"message": "Auth API running. Visit /docs for documentation."})

    @app.get("/dashboard", include_in_schema=False)
    async def serve_dashboard():
        dashboard_path = os.path.join(STATIC_DIR, "dashboard.html")
        if os.path.exists(dashboard_path):
            return FileResponse(dashboard_path)
        return JSONResponse({"message": "Dashboard not found."}, status_code=404)

    return app
