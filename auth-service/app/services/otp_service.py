"""
OTP (One-Time Password) service for email-based authentication
"""

import redis
import secrets
import string
from typing import Optional
from datetime import timedelta

from ..core.config import get_settings

settings = get_settings()

class OTPService:
    def __init__(self):
        self.redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
        self.otp_length = settings.OTP_LENGTH
        self.expire_minutes = settings.OTP_EXPIRE_MINUTES

    async def generate_otp(self, email: str) -> str:
        """Generate and store OTP for email"""
        # Generate random OTP
        otp = ''.join(secrets.choice(string.digits) for _ in range(self.otp_length))
        
        # Store in Redis with expiration
        key = f"otp:{email}"
        self.redis_client.setex(
            key, 
            timedelta(minutes=self.expire_minutes),
            otp
        )
        
        return otp

    async def verify_otp(self, email: str, provided_otp: str) -> bool:
        """Verify OTP for email"""
        key = f"otp:{email}"
        stored_otp = self.redis_client.get(key)
        
        if not stored_otp:
            return False
        
        # Verify OTP matches
        if stored_otp == provided_otp:
            # Delete OTP after successful verification
            self.redis_client.delete(key)
            return True
        
        return False

    async def get_remaining_time(self, email: str) -> Optional[int]:
        """Get remaining time for OTP in seconds"""
        key = f"otp:{email}"
        return self.redis_client.ttl(key) if self.redis_client.exists(key) else None