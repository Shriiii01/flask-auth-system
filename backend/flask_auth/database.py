from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
from config import Config

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

