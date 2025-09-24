"""
Simple email service that logs to console (for development without SMTP)
"""

from typing import Optional
import logging

logger = logging.getLogger(__name__)

class SimpleEmailService:
    def __init__(self):
        pass

    async def send_otp_email(self, email: str, otp: str) -> bool:
        """Send OTP via email (logs to console for development)"""
        try:
            message = f"""
            ===========================================
            OTP EMAIL FOR: {email}
            ===========================================
            Your verification code is: {otp}
            
            This code will expire in 10 minutes.
            ===========================================
            """
            print(message)
            logger.info(f"OTP sent to {email}: {otp}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send OTP email: {e}")
            return False

    async def send_admin_notification(self, signup_email: str, display_name: str, 
                                    provider: str) -> bool:
        """Send notification to admin about new signup request"""
        try:
            message = f"""
            ===========================================
            ADMIN NOTIFICATION
            ===========================================
            New signup request:
            Email: {signup_email}
            Name: {display_name}
            Provider: {provider}
            ===========================================
            """
            print(message)
            logger.info(f"Admin notification: New signup from {signup_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send admin notification: {e}")
            return False

    async def send_approval_notification(self, email: str, display_name: str) -> bool:
        """Send approval notification to user"""
        try:
            message = f"""
            ===========================================
            APPROVAL EMAIL FOR: {email}
            ===========================================
            Hello {display_name},
            
            Your account has been approved! You can now log in.
            ===========================================
            """
            print(message)
            logger.info(f"Approval notification sent to {email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send approval notification: {e}")
            return False