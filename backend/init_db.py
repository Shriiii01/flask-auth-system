#!/usr/bin/env python3
"""
Initialize database tables in Supabase.
This script creates all necessary tables for the authentication system.
"""
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.pool import NullPool
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get database URL from environment
DATABASE_URL = os.getenv("DATABASE_URL", os.getenv("SUPABASE_DATABASE_URL"))

if not DATABASE_URL or "[YOUR-PASSWORD]" in DATABASE_URL:
    print("❌ ERROR: DATABASE_URL not set or contains placeholder!")
    print("\n💡 Please update your .env file with your actual Supabase password:")
    print("   DATABASE_URL=postgresql://postgres:YOUR_ACTUAL_PASSWORD@db.shbmmpyqbojzwafpnetk.supabase.co:5432/postgres")
    sys.exit(1)

Base = declarative_base()

# Import models to register them
from flask_auth.models import User

def init_database():
    """Create all database tables"""
    print("🚀 Initializing database...")
    print(f"📊 Connecting to Supabase...")
    
    try:
        # Create engine
        if "sqlite" in DATABASE_URL:
            engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
        else:
            engine = create_engine(
                DATABASE_URL,
                poolclass=NullPool,
                pool_pre_ping=True,
                connect_args={
                    "sslmode": "require" if "supabase.co" in DATABASE_URL else "prefer"
                }
            )
        
        # Create all tables
        Base.metadata.create_all(bind=engine)
        print("✅ Database tables created successfully!")
        print("\n📋 Created tables:")
        print("   - user (stores email, username, password_hash)")
        print("\n✨ You can now sign up and login users!")
        print("\n🔗 Test it:")
        print("   1. Start the server: python run.py")
        print("   2. Visit: http://localhost:5001")
        print("   3. Sign up a new user")
        return True
    except Exception as e:
        print(f"❌ Error creating tables: {str(e)}")
        print("\n💡 Make sure:")
        print("   1. DATABASE_URL is set correctly in .env")
        print("   2. Your Supabase password is correct (replace [YOUR-PASSWORD])")
        print("   3. Your Supabase project is active")
        print("   4. You have internet connection to Supabase")
        return False

if __name__ == "__main__":
    success = init_database()
    sys.exit(0 if success else 1)
