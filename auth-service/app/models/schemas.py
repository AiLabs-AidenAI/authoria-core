"""
Pydantic schemas for request/response validation
"""

from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, Dict, Any, List, Union
from datetime import datetime
import uuid


class SignupRequest(BaseModel):
    email: EmailStr
    password: Optional[str] = None
    display_name: Optional[str] = None
    tenant_id: Optional[uuid.UUID] = None
    requested_app_id: Optional[uuid.UUID] = None
    provider: str = "local_password"

    @validator('display_name', pre=True, always=True)
    def set_display_name(cls, v, values):
        if v is None and 'email' in values:
            return values['email'].split('@')[0]
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)


class OTPRequest(BaseModel):
    email: EmailStr


class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp: str = Field(..., min_length=4, max_length=8)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    email: str
    refresh_token: Optional[str] = None


class MessageResponse(BaseModel):
    message: str
    data: Optional[Dict[str, Any]] = None


class PaginatedResponse(BaseModel):
    items: List[Dict[str, Any]]
    total: int
    page: int
    limit: int
    total_pages: int


class UserProfile(BaseModel):
    id: str
    email: str
    display_name: str
    is_active: bool
    is_approved: bool
    is_admin: bool
    created_at: datetime
    last_login: Optional[datetime] = None
    login_modes: Dict[str, bool]
    providers: List[Dict[str, Any]]


class PendingSignupResponse(BaseModel):
    id: str
    email: str
    display_name: str
    provider_requested: str
    status: str
    created_at: datetime
    processed_at: Optional[datetime] = None
    requested_by_ip: Optional[str] = None
    tenant_id: Optional[str] = None


class AuditLogResponse(BaseModel):
    id: str
    actor_user_id: Optional[str] = None
    action_type: str
    target_type: str
    target_id: Optional[str] = None
    payload: Dict[str, Any]
    ip_address: Optional[str] = None
    timestamp: datetime


class SystemStats(BaseModel):
    total_users: int
    active_users: int
    pending_signups: int
    login_attempts_today: int
    successful_logins_today: int
    failed_logins_today: int
    most_used_provider: str
    recent_signups: int


class ProviderConfig(BaseModel):
    name: str
    enabled: bool
    config: Dict[str, Any]


class SMTPSettings(BaseModel):
    host: str
    port: int
    username: str
    password: str
    from_email: str
    use_tls: bool = True


class AuthSettings(BaseModel):
    require_admin_approval: bool = True
    auto_approve_domains: List[str] = []
    password_policy: Dict[str, Any]
    session_timeout_minutes: int = 15
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30


class HealthCheck(BaseModel):
    status: str
    timestamp: datetime
    version: str
    database: str
    redis: str
    services: Dict[str, str]


class ErrorResponse(BaseModel):
    error: str
    detail: str
    timestamp: datetime


# Provider-specific schemas
class GoogleOAuthConfig(BaseModel):
    client_id: str
    client_secret: str
    redirect_uri: str


class AzureOAuthConfig(BaseModel):
    client_id: str
    client_secret: str
    tenant_id: str
    redirect_uri: str


# Bulk operation schemas
class BulkUserOperation(BaseModel):
    user_ids: List[uuid.UUID]
    operation: str  # enable, disable, delete
    reason: Optional[str] = None


class BulkOperationResult(BaseModel):
    success_count: int
    failure_count: int
    successful_operations: List[Dict[str, Any]]
    failed_operations: List[Dict[str, Any]]


class CreateUserRequest(BaseModel):
    email: EmailStr
    display_name: str = Field(..., min_length=2, max_length=100)
    password: Optional[str] = Field(None, min_length=8, max_length=128)
    is_admin: bool = False


class UpdateUserRequest(BaseModel):
    display_name: Optional[str] = Field(None, min_length=2, max_length=100)
    is_admin: Optional[bool] = None
    is_approved: Optional[bool] = None


# Integration schemas
class RBACUserMapping(BaseModel):
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    roles: List[str]
    permissions: List[str]


class WebhookEvent(BaseModel):
    event_type: str
    timestamp: datetime
    user_id: Optional[uuid.UUID] = None
    data: Dict[str, Any]


# Filter and search schemas  
class UserFilters(BaseModel):
    tenant_id: Optional[uuid.UUID] = None
    is_active: Optional[bool] = None
    is_approved: Optional[bool] = None
    provider: Optional[str] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None


class PendingSignupFilters(BaseModel):
    status: str = "pending"
    provider: Optional[str] = None
    tenant_id: Optional[uuid.UUID] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None


class AuditLogFilters(BaseModel):
    action_type: Optional[str] = None
    target_type: Optional[str] = None
    actor_user_id: Optional[uuid.UUID] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None