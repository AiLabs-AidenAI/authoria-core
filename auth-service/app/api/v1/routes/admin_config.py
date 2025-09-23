"""
Admin configuration API routes
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from typing import List, Optional
from pydantic import BaseModel, Field
import uuid
from datetime import datetime

from app.core.database import get_db
from app.models.auth_config import AuthProvider, SMTPConfig, AuthSettings, ClientApplication, EmailTemplate
from app.core.security import get_current_admin_user
from app.core.encryption import encrypt_value, decrypt_value

router = APIRouter(prefix="/admin/config", tags=["admin-config"])


# Pydantic schemas
class AuthProviderCreate(BaseModel):
    name: str = Field(..., max_length=100)
    display_name: str = Field(..., max_length=200)
    provider_type: str = Field(..., max_length=50)
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    authorization_url: Optional[str] = None
    token_url: Optional[str] = None
    userinfo_url: Optional[str] = None
    scope: str = "openid profile email"
    entity_id: Optional[str] = None
    sso_url: Optional[str] = None
    x509_cert: Optional[str] = None
    auto_approve_domains: Optional[List[str]] = []
    require_email_verification: bool = True
    enabled: bool = False
    icon_url: Optional[str] = None
    description: Optional[str] = None
    config_metadata: Optional[dict] = {}


class AuthProviderResponse(BaseModel):
    id: uuid.UUID
    name: str
    display_name: str
    provider_type: str
    client_id: Optional[str]
    authorization_url: Optional[str]
    token_url: Optional[str]
    userinfo_url: Optional[str]
    scope: str
    auto_approve_domains: Optional[List[str]]
    require_email_verification: bool
    enabled: bool
    icon_url: Optional[str]
    description: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]


class SMTPConfigCreate(BaseModel):
    name: str = Field(..., max_length=100)
    host: str = Field(..., max_length=255)
    port: int = Field(default=587, ge=1, le=65535)
    username: Optional[str] = None
    password: Optional[str] = None
    use_tls: bool = True
    use_ssl: bool = False
    from_email: str = Field(..., max_length=255)
    from_name: Optional[str] = None
    reply_to: Optional[str] = None
    max_emails_per_hour: int = Field(default=100, ge=1)
    enabled: bool = False
    is_default: bool = False


class SMTPConfigResponse(BaseModel):
    id: uuid.UUID
    name: str
    host: str
    port: int
    username: Optional[str]
    use_tls: bool
    use_ssl: bool
    from_email: str
    from_name: Optional[str]
    reply_to: Optional[str]
    max_emails_per_hour: int
    enabled: bool
    is_default: bool
    created_at: datetime
    updated_at: Optional[datetime]


class AuthSettingsUpdate(BaseModel):
    access_token_expire_minutes: Optional[int] = Field(None, ge=1, le=1440)
    refresh_token_expire_days: Optional[int] = Field(None, ge=1, le=365)
    password_min_length: Optional[int] = Field(None, ge=6, le=50)
    password_require_uppercase: Optional[bool] = None
    password_require_lowercase: Optional[bool] = None
    password_require_numbers: Optional[bool] = None
    password_require_special: Optional[bool] = None
    login_rate_limit: Optional[int] = Field(None, ge=1, le=100)
    signup_rate_limit: Optional[int] = Field(None, ge=1, le=50)
    otp_rate_limit: Optional[int] = Field(None, ge=1, le=20)
    otp_length: Optional[int] = Field(None, ge=4, le=10)
    otp_expire_minutes: Optional[int] = Field(None, ge=1, le=60)
    require_admin_approval: Optional[bool] = None
    auto_approve_verified_emails: Optional[bool] = None
    enable_mfa: Optional[bool] = None
    session_timeout_minutes: Optional[int] = Field(None, ge=5, le=1440)


class ClientApplicationCreate(BaseModel):
    name: str = Field(..., max_length=200)
    description: Optional[str] = None
    redirect_uris: List[str] = []
    allowed_origins: List[str] = []
    allowed_scopes: List[str] = ["openid", "profile", "email"]
    allowed_grant_types: List[str] = ["authorization_code", "refresh_token"]
    access_token_lifetime: Optional[int] = None
    refresh_token_lifetime: Optional[int] = None
    require_pkce: bool = True
    enabled: bool = True
    logo_url: Optional[str] = None
    website_url: Optional[str] = None
    contact_email: Optional[str] = None


class ClientApplicationResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str]
    client_id: str
    redirect_uris: List[str]
    allowed_origins: List[str]
    allowed_scopes: List[str]
    allowed_grant_types: List[str]
    access_token_lifetime: Optional[int]
    refresh_token_lifetime: Optional[int]
    require_pkce: bool
    enabled: bool
    logo_url: Optional[str]
    website_url: Optional[str]
    contact_email: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]


# Auth Provider endpoints
@router.get("/providers", response_model=List[AuthProviderResponse])
async def get_auth_providers(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """Get all configured auth providers"""
    result = await db.execute(select(AuthProvider))
    providers = result.scalars().all()
    return providers


@router.post("/providers", response_model=AuthProviderResponse)
async def create_auth_provider(
    provider_data: AuthProviderCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """Create a new auth provider configuration"""
    provider = AuthProvider(**provider_data.dict())
    
    # Encrypt sensitive fields
    if provider.client_secret:
        provider.client_secret = await encrypt_value(provider.client_secret)
    
    db.add(provider)
    await db.commit()
    await db.refresh(provider)
    return provider


@router.put("/providers/{provider_id}", response_model=AuthProviderResponse)
async def update_auth_provider(
    provider_id: uuid.UUID,
    provider_data: AuthProviderCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """Update an auth provider configuration"""
    result = await db.execute(select(AuthProvider).where(AuthProvider.id == provider_id))
    provider = result.scalar_one_or_none()
    
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    
    update_data = provider_data.dict(exclude_unset=True)
    
    # Encrypt client_secret if provided
    if "client_secret" in update_data and update_data["client_secret"]:
        update_data["client_secret"] = await encrypt_value(update_data["client_secret"])
    
    await db.execute(
        update(AuthProvider)
        .where(AuthProvider.id == provider_id)
        .values(**update_data)
    )
    await db.commit()
    await db.refresh(provider)
    return provider


@router.delete("/providers/{provider_id}")
async def delete_auth_provider(
    provider_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """Delete an auth provider"""
    await db.execute(delete(AuthProvider).where(AuthProvider.id == provider_id))
    await db.commit()
    return {"message": "Provider deleted successfully"}


# SMTP Configuration endpoints
@router.get("/smtp", response_model=List[SMTPConfigResponse])
async def get_smtp_configs(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """Get all SMTP configurations"""
    result = await db.execute(select(SMTPConfig))
    configs = result.scalars().all()
    return configs


@router.post("/smtp", response_model=SMTPConfigResponse)
async def create_smtp_config(
    smtp_data: SMTPConfigCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """Create a new SMTP configuration"""
    smtp_config = SMTPConfig(**smtp_data.dict())
    
    # Encrypt password
    if smtp_config.password:
        smtp_config.password = await encrypt_value(smtp_config.password)
    
    # If this is set as default, unset others
    if smtp_config.is_default:
        await db.execute(
            update(SMTPConfig).values(is_default=False)
        )
    
    db.add(smtp_config)
    await db.commit()
    await db.refresh(smtp_config)
    return smtp_config


@router.put("/smtp/{config_id}", response_model=SMTPConfigResponse)
async def update_smtp_config(
    config_id: uuid.UUID,
    smtp_data: SMTPConfigCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """Update SMTP configuration"""
    result = await db.execute(select(SMTPConfig).where(SMTPConfig.id == config_id))
    config = result.scalar_one_or_none()
    
    if not config:
        raise HTTPException(status_code=404, detail="SMTP config not found")
    
    update_data = smtp_data.dict(exclude_unset=True)
    
    # Encrypt password if provided
    if "password" in update_data and update_data["password"]:
        update_data["password"] = await encrypt_value(update_data["password"])
    
    # Handle default flag
    if update_data.get("is_default"):
        await db.execute(
            update(SMTPConfig).values(is_default=False)
        )
    
    await db.execute(
        update(SMTPConfig)
        .where(SMTPConfig.id == config_id)
        .values(**update_data)
    )
    await db.commit()
    await db.refresh(config)
    return config


@router.delete("/smtp/{config_id}")
async def delete_smtp_config(
    config_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """Delete SMTP configuration"""
    await db.execute(delete(SMTPConfig).where(SMTPConfig.id == config_id))
    await db.commit()
    return {"message": "SMTP config deleted successfully"}


# Auth Settings endpoints
@router.get("/settings")
async def get_auth_settings(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """Get authentication settings"""
    result = await db.execute(select(AuthSettings))
    settings = result.scalar_one_or_none()
    
    if not settings:
        # Create default settings
        settings = AuthSettings()
        db.add(settings)
        await db.commit()
        await db.refresh(settings)
    
    return settings


@router.put("/settings")
async def update_auth_settings(
    settings_data: AuthSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """Update authentication settings"""
    result = await db.execute(select(AuthSettings))
    settings = result.scalar_one_or_none()
    
    if not settings:
        settings = AuthSettings()
        db.add(settings)
    
    update_data = settings_data.dict(exclude_unset=True)
    
    await db.execute(
        update(AuthSettings)
        .where(AuthSettings.id == settings.id)
        .values(**update_data)
    )
    await db.commit()
    await db.refresh(settings)
    return settings


# Client Applications endpoints
@router.get("/clients", response_model=List[ClientApplicationResponse])
async def get_client_applications(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """Get all client applications"""
    result = await db.execute(select(ClientApplication))
    clients = result.scalars().all()
    return clients


@router.post("/clients", response_model=ClientApplicationResponse)
async def create_client_application(
    client_data: ClientApplicationCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """Create a new client application"""
    import secrets
    
    client = ClientApplication(**client_data.dict())
    client.client_id = f"client_{secrets.token_urlsafe(16)}"
    client.client_secret = await encrypt_value(secrets.token_urlsafe(32))
    
    db.add(client)
    await db.commit()
    await db.refresh(client)
    return client


@router.put("/clients/{client_id}", response_model=ClientApplicationResponse)
async def update_client_application(
    client_id: uuid.UUID,
    client_data: ClientApplicationCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """Update client application"""
    result = await db.execute(select(ClientApplication).where(ClientApplication.id == client_id))
    client = result.scalar_one_or_none()
    
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    update_data = client_data.dict(exclude_unset=True)
    
    await db.execute(
        update(ClientApplication)
        .where(ClientApplication.id == client_id)
        .values(**update_data)
    )
    await db.commit()
    await db.refresh(client)
    return client


@router.delete("/clients/{client_id}")
async def delete_client_application(
    client_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """Delete client application"""
    await db.execute(delete(ClientApplication).where(ClientApplication.id == client_id))
    await db.commit()
    return {"message": "Client application deleted successfully"}


@router.post("/clients/{client_id}/regenerate-secret")
async def regenerate_client_secret(
    client_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_admin_user)
):
    """Regenerate client secret"""
    import secrets
    
    result = await db.execute(select(ClientApplication).where(ClientApplication.id == client_id))
    client = result.scalar_one_or_none()
    
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    new_secret = secrets.token_urlsafe(32)
    encrypted_secret = await encrypt_value(new_secret)
    
    await db.execute(
        update(ClientApplication)
        .where(ClientApplication.id == client_id)
        .values(client_secret=encrypted_secret)
    )
    await db.commit()
    
    return {"client_secret": new_secret}  # Return plaintext once for copying