"""
Simple Email service implementation for OTP delivery
Fallback for when full SMTP is not configured
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

class SimpleEmailService:
    """Simple email service that logs emails instead of sending them"""
    
    def __init__(self):
        self.enabled = False
        logger.info("SimpleEmailService initialized - emails will be logged only")

    async def send_otp_email(self, email: str, otp: str) -> bool:
        """Log OTP instead of sending email"""
        try:
            logger.info(f"""
            ===============================================
            OTP EMAIL (would be sent to: {email})
            ===============================================
            Your verification code is: {otp}
            This code will expire in 10 minutes.
            ===============================================
            """)
            print(f"\n🔐 OTP for {email}: {otp}\n")
            return True
        except Exception as e:
            logger.error(f"Failed to log OTP: {e}")
            return False

    async def send_admin_notification(self, signup_email: str, display_name: str, provider: str) -> bool:
        """Log admin notification"""
        logger.info(f"Admin notification: New signup from {signup_email} ({display_name}) via {provider}")
        return True

    async def send_approval_notification(self, email: str, display_name: str) -> bool:
        """Log approval notification"""
        logger.info(f"Approval notification sent to {email} ({display_name})")
        return True