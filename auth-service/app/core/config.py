"""
Configuration management for the authentication service
"""

from pydantic_settings import BaseSettings
from typing import List, Optional
from functools import lru_cache


class Settings(BaseSettings):
    # Application settings
    APP_NAME: str = "Authentication Service"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://user:password@localhost:5432/auth_db"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379"
    
    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    
    # CORS
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]
    
    # Email settings
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    FROM_EMAIL: str = "noreply@yourapp.com"
    
    # OAuth providers
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/v1/auth/oauth/google/callback"
    
    AZURE_CLIENT_ID: str = ""
    AZURE_CLIENT_SECRET: str = ""
    AZURE_TENANT_ID: str = ""
    AZURE_REDIRECT_URI: str = "http://localhost:8000/v1/auth/oauth/azure/callback"
    
    # Rate limiting
    LOGIN_RATE_LIMIT: int = 5  # attempts per minute
    SIGNUP_RATE_LIMIT: int = 3  # attempts per minute
    OTP_RATE_LIMIT: int = 3    # requests per minute
    
    # OTP settings
    OTP_LENGTH: int = 6
    OTP_EXPIRE_MINUTES: int = 10
    
    # Service URL
    BASE_URL: str = "http://localhost:8000"
    
    # RBAC service integration
    RBAC_SERVICE_URL: str = "http://localhost:8001"
    RBAC_SERVICE_TOKEN: str = ""
    
    # Password policy
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_NUMBERS: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    
    # Auto-approval settings
    AUTO_APPROVE_DOMAINS: List[str] = []  # Domains that auto-approve
    REQUIRE_ADMIN_APPROVAL: bool = True
    
    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()