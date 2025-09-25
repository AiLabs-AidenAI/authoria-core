"""
Database models for authentication service
"""

from sqlalchemy import Column, String, Boolean, DateTime, Text, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.core.database import Base
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid



class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=True)  # For multi-tenant support
    email = Column(String(255), unique=True, nullable=False, index=True)
    display_name = Column(String(255), nullable=False)
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    password_hash = Column(String(255), nullable=True)  # Nullable for SSO-only users
    role = Column(String(50), default="user")
    is_active = Column(Boolean, default=False)
    is_approved = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)
    email_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    metadata = Column(JSONB, default=dict)
    
    # Relationships
    auth_providers = relationship("AuthProviderLink", back_populates="user", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan") 
    login_attempts = relationship("LoginAttempt", back_populates="user", cascade="all, delete-orphan")
    
    # Role relationship - will be updated after role.py is imported
    # roles = relationship("Role", secondary="user_roles", back_populates="users")
    
    __table_args__ = (
        Index("idx_users_tenant_email", "tenant_id", "email"),
        Index("idx_users_active_approved", "is_active", "is_approved"),
    )


class AuthProviderLink(Base):
    __tablename__ = "auth_provider_links"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    provider_name = Column(String(50), nullable=False)  # 'local_password', 'google', 'azure', 'otp'
    external_id = Column(String(255), nullable=True)  # Provider's user ID
    is_enabled = Column(Boolean, default=True)
    linked_at = Column(DateTime, default=datetime.utcnow)
    metadata = Column(JSONB, default=dict)  # Provider-specific data
    
    user = relationship("User", back_populates="auth_providers")
    
    __table_args__ = (
        Index("idx_provider_external", "provider_name", "external_id"),
        Index("idx_user_provider", "user_id", "provider_name"),
    )


class PendingSignup(Base):
    __tablename__ = "pending_signups"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=True)
    email = Column(String(255), nullable=False, index=True)
    display_name = Column(String(255), nullable=False)
    provider_requested = Column(String(50), nullable=False)  # Which provider they want to use
    payload = Column(JSONB, default=dict)  # Signup data (hashed password, provider info, etc.)
    status = Column(String(20), default="pending")  # pending, approved, rejected
    requested_app_id = Column(UUID(as_uuid=True), nullable=True)
    requested_by_ip = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    processed_at = Column(DateTime, nullable=True)
    processed_by = Column(UUID(as_uuid=True), nullable=True)  # Admin user ID
    rejection_reason = Column(Text, nullable=True)
    
    __table_args__ = (
        Index("idx_pending_status", "status"),
        Index("idx_pending_tenant_status", "tenant_id", "status"),
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(255), nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    revoked = Column(Boolean, default=False)
    replaced_by = Column(UUID(as_uuid=True), nullable=True)  # Points to new token in rotation
    device_info = Column(JSONB, default=dict)  # User agent, IP, etc.
    
    user = relationship("User", back_populates="refresh_tokens")
    
    __table_args__ = (
        Index("idx_token_hash", "token_hash"),
        Index("idx_user_active_tokens", "user_id", "revoked_at"),
    )


class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    email = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False)
    provider = Column(String(50), nullable=False)
    success = Column(Boolean, nullable=False)
    failure_reason = Column(String(255), nullable=True)
    user_agent = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="login_attempts")
    
    __table_args__ = (
        Index("idx_login_attempts_ip_timestamp", "ip_address", "timestamp"),
        Index("idx_login_attempts_email_timestamp", "email", "timestamp"),
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_user_id = Column(UUID(as_uuid=True), nullable=True)  # Who performed the action
    action_type = Column(String(50), nullable=False)  # signup_requested, user_approved, login_success, etc.
    target_type = Column(String(50), nullable=False)  # user, pending_signup, etc.
    target_id = Column(UUID(as_uuid=True), nullable=True)
    payload = Column(JSONB, default=dict)  # Additional context
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index("idx_audit_actor_timestamp", "actor_user_id", "timestamp"),
        Index("idx_audit_action_timestamp", "action_type", "timestamp"),
        Index("idx_audit_target", "target_type", "target_id"),
    )


class TenantClient(Base):
    """Minimal tenant information for auth service"""
    __tablename__ = "tenant_clients"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    domain = Column(String(255), nullable=True)  # For domain-based auto-approval
    auto_approve = Column(Boolean, default=False)
    default_role_id = Column(UUID(as_uuid=True), nullable=True)
    settings = Column(JSONB, default=dict)  # Tenant-specific auth settings
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    __table_args__ = (
        Index("idx_tenant_domain", "domain"),
    )