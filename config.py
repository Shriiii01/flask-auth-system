from dotenv import load_dotenv
import os
from datetime import timedelta

load_dotenv()

class Config:
    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///instance/app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Security
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-123")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-jwt-secret-key-123")
    
    # Environment
    ENV = os.getenv("FLASK_ENV", "development")
    DEBUG = ENV == "development"
    
    # JWT Configuration
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", "1")))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES", "30")))
    JWT_ERROR_MESSAGE_KEY = "message"
    
    # CORS Configuration
    CORS_HEADERS = 'Content-Type'

    # Email Configuration
    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True").lower() == "true"
    MAIL_USERNAME = os.getenv("EMAIL_SENDER")
    MAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.getenv("EMAIL_SENDER")

    # OAuth Configuration
    GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
    GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
    
    # Application URL
    BASE_URL = os.getenv("BASE_URL", "http://localhost:5001")
    
    # Redis Configuration
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # Rate Limiter Configuration
    RATELIMIT_STORAGE_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    RATELIMIT_STRATEGY = "fixed-window"
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_DEFAULTS = ["error_message=429 Too Many Requests"]