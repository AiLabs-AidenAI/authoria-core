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
        self.from_email = settings.FROM_EMAIL or "noreply@yourapp.com"
        
        # Check if SMTP is configured
        self.enabled = bool(self.smtp_host and self.smtp_user and self.smtp_password)
        
        # Setup Jinja2 templates
        template_dir = os.path.join(os.path.dirname(__file__), '../templates')
        self.jinja_env = Environment(loader=FileSystemLoader(template_dir))
        
        if not self.enabled:
            print("⚠️  SMTP not configured. Emails will be logged to console only.")
            print("   Configure SMTP_HOST, SMTP_USER, SMTP_PASSWORD in environment variables.")

    async def send_otp_email(self, email: str, otp: str) -> bool:
        """Send OTP via email"""
        try:
            if not self.enabled:
                # Fallback to console logging
                print(f"""
                ===============================================
                OTP EMAIL (would be sent to: {email})
                ===============================================
                Your verification code is: {otp}
                This code will expire in {settings.OTP_EXPIRE_MINUTES} minutes.
                ===============================================
                """)
                return True
            
            # Render email template
            try:
                template = self.jinja_env.get_template('otp_email.html')
                html_content = template.render(
                    otp=otp,
                    expire_minutes=settings.OTP_EXPIRE_MINUTES,
                    app_name=settings.APP_NAME
                )
            except Exception:
                # Fallback to simple HTML if template fails
                html_content = f"""
                <html>
                <body>
                <h2>{settings.APP_NAME} - Verification Code</h2>
                <p>Your verification code is: <strong>{otp}</strong></p>
                <p>This code will expire in {settings.OTP_EXPIRE_MINUTES} minutes.</p>
                </body>
                </html>
                """
            
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
                use_tls=True,
                start_tls=True
            )
            
            print(f"✅ OTP email sent successfully to {email}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to send OTP email to {email}: {e}")
            # Fallback to console logging on error
            print(f"""
            ===============================================
            OTP EMAIL FALLBACK (failed to send to: {email})
            ===============================================
            Your verification code is: {otp}
            This code will expire in {settings.OTP_EXPIRE_MINUTES} minutes.
            ===============================================
            """)
            return True  # Return True so OTP flow continues

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