from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
from config import Config

# Ensure SQLite directory exists when using local file DB
_db_url = make_url(Config.DATABASE_URL)
if _db_url.drivername == "sqlite" and _db_url.database and _db_url.database != ":memory:":
    Path(_db_url.database).parent.mkdir(parents=True, exist_ok=True)

# Supabase uses PostgreSQL, so we configure the engine accordingly
if "sqlite" in Config.DATABASE_URL:
    # SQLite configuration (for local development)
    engine = create_engine(
        Config.DATABASE_URL,
        connect_args={"check_same_thread": False},
        echo=Config.DEBUG
    )
else:
    # PostgreSQL/Supabase configuration
    # Use NullPool for serverless/connection pooling environments like Supabase
    engine = create_engine(
        Config.DATABASE_URL,
        poolclass=NullPool,  # Supabase handles connection pooling
        echo=Config.DEBUG,
        pool_pre_ping=True,  # Verify connections before using
        connect_args={
            "sslmode": "require" if "supabase.co" in Config.DATABASE_URL else "prefer"
        }
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """Dependency for FastAPI to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

