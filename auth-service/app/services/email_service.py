"""
Email service for sending OTPs and notifications
"""

import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Environment, FileSystemLoader
from typing import Optional
import os

from ..core.config import get_settings

settings = get_settings()

class EmailService:
    def __init__(self):
        self.smtp_host = settings.SMTP_HOST
        self.smtp_port = settings.SMTP_PORT
        self.smtp_user = settings.SMTP_USER
        self.smtp_password = settings.SMTP_PASSWORD
        self.from_email = settings.FROM_EMAIL
        
        # Setup Jinja2 templates
        template_dir = os.path.join(os.path.dirname(__file__), '../templates')
        self.jinja_env = Environment(loader=FileSystemLoader(template_dir))

    async def send_otp_email(self, email: str, otp: str) -> bool:
        """Send OTP via email"""
        try:
            # Render email template
            template = self.jinja_env.get_template('otp_email.html')
            html_content = template.render(
                otp=otp,
                expire_minutes=settings.OTP_EXPIRE_MINUTES,
                app_name=settings.APP_NAME
            )
            
            # Create message
            message = MIMEMultipart('alternative')
            message['Subject'] = f"Your {settings.APP_NAME} verification code"
            message['From'] = self.from_email
            message['To'] = email
            
            # Add HTML part
            html_part = MIMEText(html_content, 'html')
            message.attach(html_part)
            
            # Send email
            await aiosmtplib.send(
                message,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_password,
                use_tls=True
            )
            
            return True
            
        except Exception as e:
            print(f"Failed to send OTP email: {e}")
            return False

    async def send_admin_notification(self, signup_email: str, display_name: str, 
                                    provider: str) -> bool:
        """Send notification to admin about new signup request"""
        try:
            # For now, we'll skip admin notifications
            # In production, this would send to admin email addresses
            return True
            
        except Exception as e:
            print(f"Failed to send admin notification: {e}")
            return False

    async def send_approval_notification(self, email: str, display_name: str) -> bool:
        """Send approval notification to user"""
        try:
            template = self.jinja_env.get_template('approval_email.html')
            html_content = template.render(
                display_name=display_name,
                app_name=settings.APP_NAME,
                login_url="http://localhost:3000/auth/login"  # Configure this
            )
            
            message = MIMEMultipart('alternative')
            message['Subject'] = f"Your {settings.APP_NAME} account has been approved"
            message['From'] = self.from_email
            message['To'] = email
            
            html_part = MIMEText(html_content, 'html')
            message.attach(html_part)
            
            await aiosmtplib.send(
                message,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_password,
                use_tls=True
            )
            
            return True
            
        except Exception as e:
            print(f"Failed to send approval notification: {e}")
            return False