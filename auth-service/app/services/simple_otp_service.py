"""
Simple OTP service using in-memory storage (for development without Redis)
"""

import secrets
import string
from typing import Optional, Dict
from datetime import datetime, timedelta

class SimpleOTPService:
    def __init__(self):
        self.otps: Dict[str, Dict] = {}  # email -> {otp: str, expires: datetime}
        self.otp_length = 6
        self.expire_minutes = 10

    async def generate_otp(self, email: str) -> str:
        """Generate and store OTP for email"""
        # Generate random OTP
        otp = ''.join(secrets.choice(string.digits) for _ in range(self.otp_length))
        
        # Store in memory with expiration
        self.otps[email] = {
            'otp': otp,
            'expires': datetime.utcnow() + timedelta(minutes=self.expire_minutes)
        }
        
        # Clean expired OTPs
        self._clean_expired()
        
        return otp

    async def verify_otp(self, email: str, provided_otp: str) -> bool:
        """Verify OTP for email"""
        self._clean_expired()
        
        if email not in self.otps:
            return False
        
        stored_data = self.otps[email]
        
        # Check if OTP matches and hasn't expired
        if (stored_data['otp'] == provided_otp and 
            stored_data['expires'] > datetime.utcnow()):
            # Delete OTP after successful verification
            del self.otps[email]
            return True
        
        return False

    def _clean_expired(self):
        """Remove expired OTPs"""
        now = datetime.utcnow()
        expired_emails = [
            email for email, data in self.otps.items() 
            if data['expires'] <= now
        ]
        for email in expired_emails:
            del self.otps[email]