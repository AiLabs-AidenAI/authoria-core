"""
Authentication service with comprehensive user management
"""

from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from passlib.context import CryptContext
from passlib.hash import argon2
import uuid
import secrets
import hashlib

from ..core.database import get_db
from ..core.security import create_tokens, hash_refresh_token
from ..models.user import User, AuthProviderLink, PendingSignup, RefreshToken, LoginAttempt, AuditLog
from ..providers.google_oauth import GoogleOAuthProvider
from ..providers.azure_oauth import AzureOAuthProvider
from ..core.config import get_settings

settings = get_settings()

# Password hashing
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    deprecated="auto",
    default="argon2"
)

class AuthResult:
    def __init__(self, success: bool, user_id: Optional[uuid.UUID] = None, 
                 email: Optional[str] = None, access_token: Optional[str] = None,
                 refresh_token: Optional[str] = None, error_message: Optional[str] = None):
        self.success = success
        self.user_id = user_id
        self.email = email
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.error_message = error_message


class AuthService:
    def __init__(self):
        self.oauth_providers = {
            'google': GoogleOAuthProvider({
                'client_id': settings.GOOGLE_CLIENT_ID,
                'client_secret': settings.GOOGLE_CLIENT_SECRET,
                'redirect_uri': f"{settings.BASE_URL}/v1/auth/oauth/google/callback"
            }),
            'azure': AzureOAuthProvider({
                'client_id': settings.AZURE_CLIENT_ID,
                'client_secret': settings.AZURE_CLIENT_SECRET,
                'tenant_id': settings.AZURE_TENANT_ID,
                'redirect_uri': f"{settings.BASE_URL}/v1/auth/oauth/azure/callback"
            })
        }

    async def create_signup_request(self, email: str, display_name: str = None,
                                  password: str = None, tenant_id: uuid.UUID = None,
                                  requested_app_id: uuid.UUID = None, provider: str = "local_password",
                                  ip_address: str = None) -> PendingSignup:
        """Create a new signup request pending admin approval"""
        
        async with AsyncSessionLocal() as db:
            # Check if email already exists or pending
            existing_user = await db.execute(
                select(User).where(User.email == email)
            )
            if existing_user.scalar_one_or_none():
                raise ValueError("Email already registered")
            
            existing_pending = await db.execute(
                select(PendingSignup).where(
                    and_(PendingSignup.email == email, PendingSignup.status == "pending")
                )
            )
            if existing_pending.scalar_one_or_none():
                raise ValueError("Signup request already pending approval")
            
            # Prepare payload
            payload = {
                "display_name": display_name or email.split("@")[0],
                "provider": provider
            }
            
            # Hash password if provided
            if password:
                if not self._validate_password_policy(password):
                    raise ValueError("Password does not meet security requirements")
                payload["password_hash"] = pwd_context.hash(password)
            
            # Create pending signup
            pending_signup = PendingSignup(
                email=email,
                display_name=payload["display_name"],
                tenant_id=tenant_id,
                provider_requested=provider,
                payload=payload,
                requested_app_id=requested_app_id,
                requested_by_ip=ip_address
            )
            
            db.add(pending_signup)
            await db.commit()
            await db.refresh(pending_signup)
            
            # Log audit event
            await self._log_audit(
                db, "signup_requested", "pending_signup", pending_signup.id,
                {"email": email, "provider": provider, "ip": ip_address}
            )
            
            return pending_signup

    async def approve_signup(self, pending_id: uuid.UUID, admin_user_id: uuid.UUID,
                           default_role_id: str = None) -> User:
        """Approve a pending signup and create user account"""
        
        async with AsyncSessionLocal() as db:
            # Get pending signup
            pending = await db.get(PendingSignup, pending_id)
            if not pending or pending.status != "pending":
                raise ValueError("Invalid or already processed signup request")
            
            # Create user
            user = User(
                email=pending.email,
                display_name=pending.payload.get("display_name"),
                tenant_id=pending.tenant_id,
                password_hash=pending.payload.get("password_hash"),
                is_active=True,
                is_approved=True
            )
            
            db.add(user)
            await db.flush()  # Get user ID
            
            # Create auth provider link
            provider_link = AuthProviderLink(
                user_id=user.id,
                provider_name=pending.provider_requested,
                is_enabled=True,
                metadata={"approved_by": str(admin_user_id)}
            )
            db.add(provider_link)
            
            # Update pending signup
            pending.status = "approved"
            pending.processed_at = datetime.utcnow()
            pending.processed_by = admin_user_id
            
            await db.commit()
            await db.refresh(user)
            
            # Log audit event
            await self._log_audit(
                db, "user_approved", "user", user.id,
                {"approved_by": str(admin_user_id), "email": user.email}
            )
            
            return user

    async def create_user_manually(self, email: str, display_name: str, 
                                 password: str = None, tenant_id: uuid.UUID = None,
                                 is_admin: bool = False, admin_user_id: uuid.UUID = None) -> User:
        """Create a user manually without approval process"""
        
        async with AsyncSessionLocal() as db:
            # Check if email already exists
            existing_user = await db.execute(
                select(User).where(User.email == email)
            )
            if existing_user.scalar_one_or_none():
                raise ValueError("Email already registered")
            
            # Validate password if provided
            password_hash = None
            if password:
                if not self._validate_password_policy(password):
                    raise ValueError("Password does not meet security requirements")
                password_hash = pwd_context.hash(password)
            
            # Create user
            user = User(
                email=email,
                display_name=display_name,
                tenant_id=tenant_id,
                password_hash=password_hash,
                is_active=True,
                is_approved=True,
                is_admin=is_admin
            )
            
            db.add(user)
            await db.flush()
            
            # Create auth provider link if password provided
            if password_hash:
                provider_link = AuthProviderLink(
                    user_id=user.id,
                    provider_name="local_password",
                    is_enabled=True,
                    metadata={"created_manually": True, "created_by": str(admin_user_id)}
                )
                db.add(provider_link)
            
            await db.commit()
            await db.refresh(user)
            
            # Log audit event
            await self._log_audit(
                db, "user_created_manually", "user", user.id,
                {"created_by": str(admin_user_id), "email": user.email, "is_admin": is_admin}
            )
            
            return user

    async def authenticate_user(self, email: str, password: str, 
                              ip_address: str = None, user_agent: str = None) -> AuthResult:
        """Authenticate user with email and password"""
        
        async with AsyncSessionLocal() as db:
            # Get user
            result = await db.execute(
                select(User).where(User.email == email)
            )
            user = result.scalar_one_or_none()
            
            # Log login attempt
            success = False
            failure_reason = None
            
            if not user:
                failure_reason = "User not found"
            elif not user.is_active or not user.is_approved:
                failure_reason = "Account not active or not approved"
            elif not user.password_hash:
                failure_reason = "Password authentication not enabled"
            elif not pwd_context.verify(password, user.password_hash):
                failure_reason = "Invalid password"
            else:
                success = True
            
            # Log attempt
            login_attempt = LoginAttempt(
                user_id=user.id if user else None,
                email=email,
                ip_address=ip_address or "",
                provider="local_password",
                success=success,
                failure_reason=failure_reason,
                user_agent=user_agent
            )
            db.add(login_attempt)
            
            if not success:
                await db.commit()
                return AuthResult(success=False, error_message=failure_reason)
            
            # Create tokens
            access_token, refresh_token_plain = create_tokens(user.id, user.email)
            
            # Store refresh token
            refresh_token_hash = hash_refresh_token(refresh_token_plain)
            refresh_token_record = RefreshToken(
                user_id=user.id,
                token_hash=refresh_token_hash,
                expires_at=datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
                device_info={"user_agent": user_agent, "ip": ip_address}
            )
            db.add(refresh_token_record)
            
            # Update last login
            user.last_login = datetime.utcnow()
            
            await db.commit()
            
            return AuthResult(
                success=True,
                user_id=user.id,
                email=user.email,
                access_token=access_token,
                refresh_token=refresh_token_plain
            )

    async def get_users(self, tenant_id: uuid.UUID = None, page: int = 1, 
                       limit: int = 50, search: str = None) -> Dict[str, Any]:
        """Get paginated list of users with their login modes"""
        
        async with AsyncSessionLocal() as db:
            query = select(User)
            
            if tenant_id:
                query = query.where(User.tenant_id == tenant_id)
            
            if search:
                query = query.where(
                    or_(
                        User.email.ilike(f"%{search}%"),
                        User.display_name.ilike(f"%{search}%")
                    )
                )
            
            # Get total count
            count_result = await db.execute(
                select(func.count(User.id)).select_from(query.subquery())
            )
            total = count_result.scalar()
            
            # Get paginated results
            offset = (page - 1) * limit
            users_result = await db.execute(
                query.offset(offset).limit(limit).order_by(User.created_at.desc())
            )
            users = users_result.scalars().all()
            
            # Enrich with login modes
            user_data = []
            for user in users:
                providers_result = await db.execute(
                    select(AuthProviderLink).where(AuthProviderLink.user_id == user.id)
                )
                providers = providers_result.scalars().all()
                
                login_modes = {
                    "password": any(p.provider_name == "local_password" and p.is_enabled for p in providers),
                    "otp": any(p.provider_name == "email_otp" and p.is_enabled for p in providers),
                    "google": any(p.provider_name == "google" and p.is_enabled for p in providers),
                    "azure": any(p.provider_name == "azure" and p.is_enabled for p in providers)
                }
                
                user_data.append({
                    "id": str(user.id),
                    "email": user.email,
                    "display_name": user.display_name,
                    "is_active": user.is_active,
                    "is_approved": user.is_approved,
                    "is_admin": user.is_admin,
                    "created_at": user.created_at.isoformat(),
                    "last_login": user.last_login.isoformat() if user.last_login else None,
                    "login_modes": login_modes,
                    "providers": [{"name": p.provider_name, "enabled": p.is_enabled} for p in providers]
                })
            
            return {
                "users": user_data,
                "total": total,
                "page": page,
                "limit": limit,
                "total_pages": (total + limit - 1) // limit
            }

    async def get_pending_signups(self, status: str = "pending", page: int = 1, 
                                limit: int = 50) -> Dict[str, Any]:
        """Get paginated list of pending signups"""
        
        async with AsyncSessionLocal() as db:
            query = select(PendingSignup)
            if status != "all":
                query = query.where(PendingSignup.status == status)
            
            # Get total count
            count_result = await db.execute(
                select(func.count(PendingSignup.id)).select_from(query.subquery())
            )
            total = count_result.scalar()
            
            # Get paginated results
            offset = (page - 1) * limit
            result = await db.execute(
                query.offset(offset).limit(limit).order_by(PendingSignup.created_at.desc())
            )
            signups = result.scalars().all()
            
            signup_data = []
            for signup in signups:
                signup_data.append({
                    "id": str(signup.id),
                    "email": signup.email,
                    "display_name": signup.display_name,
                    "provider_requested": signup.provider_requested,
                    "status": signup.status,
                    "created_at": signup.created_at.isoformat(),
                    "processed_at": signup.processed_at.isoformat() if signup.processed_at else None,
                    "requested_by_ip": signup.requested_by_ip,
                    "tenant_id": str(signup.tenant_id) if signup.tenant_id else None
                })
            
            return {
                "signups": signup_data,
                "total": total,
                "page": page,
                "limit": limit,
                "total_pages": (total + limit - 1) // limit
            }

    def _validate_password_policy(self, password: str) -> bool:
        """Validate password against security policy"""
        if len(password) < settings.PASSWORD_MIN_LENGTH:
            return False
        
        if settings.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            return False
        
        if settings.PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            return False
        
        if settings.PASSWORD_REQUIRE_NUMBERS and not any(c.isdigit() for c in password):
            return False
        
        if settings.PASSWORD_REQUIRE_SPECIAL and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            return False
        
        return True

    async def _log_audit(self, db: AsyncSession, action_type: str, target_type: str,
                        target_id: uuid.UUID, payload: Dict[str, Any] = None,
                        actor_user_id: uuid.UUID = None, ip_address: str = None):
        """Log audit event"""
        audit_log = AuditLog(
            actor_user_id=actor_user_id,
            action_type=action_type,
            target_type=target_type,
            target_id=target_id,
            payload=payload or {},
            ip_address=ip_address
        )
        db.add(audit_log)
        
# Import required for database queries
from sqlalchemy import func
from ..core.database import AsyncSessionLocal