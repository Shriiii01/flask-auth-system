#!/usr/bin/env python3
"""Create database tables using the same engine and models as the FastAPI app."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv

load_dotenv()

from auth.database import Base, engine
from auth.models import User  # noqa: F401 — register models on Base.metadata


def init_database() -> bool:
    try:
        Base.metadata.create_all(bind=engine)
        print("Database tables created successfully (see auth.models).")
        return True
    except Exception as e:
        print(f"Error creating tables: {e}")
        return False


if __name__ == "__main__":
    sys.exit(0 if init_database() else 1)
