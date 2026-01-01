from dotenv import load_dotenv
import os
from datetime import timedelta

load_dotenv()

class Config:
    # Supabase Database URL
    # Format: postgresql://postgres:[PASSWORD]@db.[PROJECT-REF].supabase.co:5432/postgres
    # Or use connection pooling: postgresql://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[region].pooler.supabase.com:6543/postgres
    DATABASE_URL = os.getenv("DATABASE_URL", os.getenv("SUPABASE_DATABASE_URL", "sqlite:///instance/app.db"))
    
    # Supabase Project Settings (optional, for Supabase client)
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_KEY = os.getenv("SUPABASE_KEY")
    SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-123")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-jwt-secret-key-123")
    JWT_ALGORITHM = "HS256"
    
    ENV = os.getenv("ENV", "development")
    DEBUG = ENV == "development"
    
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", "1")))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES", "30")))
    
    CORS_HEADERS = 'Content-Type'

    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True").lower() == "true"
    MAIL_USERNAME = os.getenv("EMAIL_SENDER")
    MAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.getenv("EMAIL_SENDER")

    
    BASE_URL = os.getenv("BASE_URL", "http://localhost:5001")
    
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    RATELIMIT_STORAGE_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    RATELIMIT_STRATEGY = "fixed-window"
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_DEFAULTS = ["error_message=429 Too Many Requests"]