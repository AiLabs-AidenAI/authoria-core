"""
Authentication configuration models
"""

from sqlalchemy import Column, String, Text, Boolean, DateTime, JSON, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base
import uuid

Base = declarative_base()


class AuthProvider(Base):
    """OAuth/SSO provider configurations"""
    __tablename__ = "auth_providers"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)  # google, azure, github, etc.
    display_name = Column(String(200), nullable=False)
    provider_type = Column(String(50), nullable=False)  # oauth2, oidc, saml
    
    # OAuth2/OIDC settings
    client_id = Column(String(500))
    client_secret = Column(Text)  # Encrypted
    authorization_url = Column(Text)
    token_url = Column(Text)
    userinfo_url = Column(Text)
    scope = Column(String(500), default="openid profile email")
    
    # SAML settings
    entity_id = Column(String(500))
    sso_url = Column(Text)
    x509_cert = Column(Text)
    
    # Configuration
    auto_approve_domains = Column(JSON)  # List of domains to auto-approve
    require_email_verification = Column(Boolean, default=True)
    enabled = Column(Boolean, default=False)
    
    # Metadata
    icon_url = Column(String(500))
    description = Column(Text)
    config_metadata = Column(JSON)  # Additional provider-specific config
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class SMTPConfig(Base):
    """SMTP configuration for email sending"""
    __tablename__ = "smtp_config"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False, unique=True)
    
    # SMTP settings
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=False, default=587)
    username = Column(String(255))
    password = Column(Text)  # Encrypted
    use_tls = Column(Boolean, default=True)
    use_ssl = Column(Boolean, default=False)
    
    # Email settings
    from_email = Column(String(255), nullable=False)
    from_name = Column(String(255))
    reply_to = Column(String(255))
    
    # Configuration
    max_emails_per_hour = Column(Integer, default=100)
    enabled = Column(Boolean, default=False)
    is_default = Column(Boolean, default=False)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class AuthSettings(Base):
    """General authentication settings"""
    __tablename__ = "auth_settings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Token settings
    access_token_expire_minutes = Column(Integer, default=15)
    refresh_token_expire_days = Column(Integer, default=30)
    jwt_algorithm = Column(String(20), default="HS256")
    
    # Password policy
    password_min_length = Column(Integer, default=8)
    password_require_uppercase = Column(Boolean, default=True)
    password_require_lowercase = Column(Boolean, default=True)
    password_require_numbers = Column(Boolean, default=True)
    password_require_special = Column(Boolean, default=True)
    
    # Rate limiting
    login_rate_limit = Column(Integer, default=5)  # per minute
    signup_rate_limit = Column(Integer, default=3)  # per minute
    otp_rate_limit = Column(Integer, default=3)    # per minute
    
    # OTP settings
    otp_length = Column(Integer, default=6)
    otp_expire_minutes = Column(Integer, default=10)
    
    # Approval settings
    require_admin_approval = Column(Boolean, default=True)
    auto_approve_verified_emails = Column(Boolean, default=False)
    
    # Security
    enable_mfa = Column(Boolean, default=False)
    session_timeout_minutes = Column(Integer, default=480)  # 8 hours
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class ClientApplication(Base):
    """Applications that consume this auth service"""
    __tablename__ = "client_applications"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    
    # OAuth client credentials
    client_id = Column(String(100), nullable=False, unique=True)
    client_secret = Column(Text, nullable=False)  # Encrypted
    
    # Allowed redirect URIs
    redirect_uris = Column(JSON)  # List of allowed redirect URIs
    allowed_origins = Column(JSON)  # CORS origins
    
    # Permissions
    allowed_scopes = Column(JSON)  # Scopes this client can request
    allowed_grant_types = Column(JSON)  # authorization_code, refresh_token, etc.
    
    # Configuration
    access_token_lifetime = Column(Integer)  # Override default if set
    refresh_token_lifetime = Column(Integer)  # Override default if set
    require_pkce = Column(Boolean, default=True)
    
    # Status
    enabled = Column(Boolean, default=True)
    
    # Metadata
    logo_url = Column(String(500))
    website_url = Column(String(500))
    contact_email = Column(String(255))
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class EmailTemplate(Base):
    """Email templates for various auth flows"""
    __tablename__ = "email_templates"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False, unique=True)
    template_type = Column(String(50), nullable=False)  # otp, welcome, approval, etc.
    
    # Template content
    subject = Column(String(500), nullable=False)
    html_content = Column(Text, nullable=False)
    text_content = Column(Text)
    
    # Variables documentation
    available_variables = Column(JSON)  # List of available template variables
    
    # Configuration
    enabled = Column(Boolean, default=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())