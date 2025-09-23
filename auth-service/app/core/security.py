"""
Security utilities and dependencies
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import jwt
from datetime import datetime, timedelta
from typing import Optional
import secrets
import hashlib

from app.core.database import get_db
from app.models.user import User
from app.core.config import get_settings

settings = get_settings()
security = HTTPBearer()


class TokenManager:
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire, "type": "access"})
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        return encoded_jwt
    
    @staticmethod
    def create_refresh_token():
        """Create a secure refresh token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def verify_token(token: str, token_type: str = "access"):
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            if payload.get("type") != token_type:
                return None
            return payload
        except jwt.PyJWTError:
            return None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Get current authenticated user"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    payload = TokenManager.verify_token(credentials.credentials)
    if payload is None:
        raise credentials_exception
    
    user_id: str = payload.get("sub")
    if user_id is None:
        raise credentials_exception
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if user is None or not user.is_active:
        raise credentials_exception
    
    return user


async def get_current_admin_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current authenticated admin user"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user


def hash_password(password: str) -> str:
    """Hash password using Argon2"""
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    return ph.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password using Argon2"""
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    
    ph = PasswordHasher()
    try:
        ph.verify(hashed_password, plain_password)
        return True
    except VerifyMismatchError:
        return False


def generate_client_credentials():
    """Generate OAuth client credentials"""
    client_id = f"client_{secrets.token_urlsafe(16)}"
    client_secret = secrets.token_urlsafe(32)
    return client_id, client_secret


def validate_password_strength(password: str) -> bool:
    """Validate password against policy"""
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        return False
    
    if settings.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        return False
    
    if settings.PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
        return False
    
    if settings.PASSWORD_REQUIRE_NUMBERS and not any(c.isdigit() for c in password):
        return False
    
    if settings.PASSWORD_REQUIRE_SPECIAL:
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(c in special_chars for c in password):
            return False
    
    return True


class RateLimiter:
    """Simple in-memory rate limiter"""
    def __init__(self):
        self.attempts = {}
    
    def is_allowed(self, key: str, limit: int, window_minutes: int = 1) -> bool:
        now = datetime.utcnow()
        window_start = now - timedelta(minutes=window_minutes)
        
        # Clean old attempts
        if key in self.attempts:
            self.attempts[key] = [
                attempt for attempt in self.attempts[key] 
                if attempt > window_start
            ]
        else:
            self.attempts[key] = []
        
        # Check if limit exceeded
        if len(self.attempts[key]) >= limit:
            return False
        
        # Record this attempt
        self.attempts[key].append(now)
        return True


# Global rate limiter instance
rate_limiter = RateLimiter()


def check_rate_limit(key: str, limit: int, window_minutes: int = 1):
    """Rate limiting dependency"""
    if not rate_limiter.is_allowed(key, limit, window_minutes):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )