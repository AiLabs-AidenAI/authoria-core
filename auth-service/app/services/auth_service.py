"""
Authentication service with comprehensive user management
"""

from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func
from passlib.context import CryptContext
from passlib.hash import argon2
import uuid
import secrets
import hashlib

from ..core.database import AsyncSessionLocal
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
                 refresh_token: Optional[str] = None, error_message: Optional[str] = None,
                 redirect_url: Optional[str] = None, new_refresh_token: Optional[str] = None):
        self.success = success
        self.user_id = user_id
        self.email = email
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.error_message = error_message
        self.redirect_url = redirect_url
        self.new_refresh_token = new_refresh_token


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
        
    async def reject_signup(self, pending_id: uuid.UUID, admin_user_id: uuid.UUID, 
                          reason: str = None) -> bool:
        """Reject a pending signup request"""
        async with AsyncSessionLocal() as db:
            # Find pending signup
            result = await db.execute(
                select(PendingSignup).where(PendingSignup.id == pending_id)
            )
            pending_signup = result.scalar_one_or_none()
            
            if not pending_signup:
                raise ValueError("Pending signup not found")
            
            if pending_signup.status != "pending":
                raise ValueError("Signup request is no longer pending")
            
            # Update status
            pending_signup.status = "rejected"
            pending_signup.rejection_reason = reason
            pending_signup.processed_at = datetime.utcnow()
            pending_signup.processed_by = str(admin_user_id)
            
            await db.commit()
            
            # Log audit event
            await self._log_audit(
                db, admin_user_id, "reject_signup", "signup_request",
                str(pending_id), {"reason": reason, "email": pending_signup.email}
            )
            
            return True

    async def authenticate_with_otp(self, email: str, ip_address: str = None, 
                                  user_agent: str = None) -> AuthResult:
        """Authenticate user with OTP (after OTP verification)"""
        async with AsyncSessionLocal() as db:
            # Find user by email
            result = await db.execute(
                select(User).where(User.email == email)
            )
            user = result.scalar_one_or_none()
            
            if not user:
                return AuthResult(False, error_message="User not found")
            
            if not user.is_active:
                return AuthResult(False, error_message="User account is inactive")
            
            if not user.is_approved:
                return AuthResult(False, error_message="User account pending approval")
            
            # Generate tokens
            access_token, refresh_token = create_tokens(user.id, user.email)
            
            # Store refresh token
            hashed_refresh = hash_refresh_token(refresh_token)
            refresh_token_obj = RefreshToken(
                user_id=user.id,
                token_hash=hashed_refresh,
                expires_at=datetime.utcnow() + timedelta(days=30)
            )
            db.add(refresh_token_obj)
            
            # Log login attempt
            login_attempt = LoginAttempt(
                user_id=user.id,
                email=email,
                ip_address=ip_address,
                provider="email_otp",
                success=True,
                user_agent=user_agent
            )
            db.add(login_attempt)
            
            # Update last login
            user.last_login = datetime.utcnow()
            
            await db.commit()
            
            return AuthResult(
                success=True,
                user_id=user.id,
                email=user.email,
                access_token=access_token,
                refresh_token=refresh_token
            )

    async def start_oauth_flow(self, provider: str, redirect_uri: str, 
                             state: str = None) -> AuthResult:
        """Start OAuth flow for external providers"""
        if provider not in self.oauth_providers:
            return AuthResult(False, error_message=f"Provider {provider} not supported")
        
        try:
            oauth_provider = self.oauth_providers[provider]
            auth_url = oauth_provider.get_authorization_url(redirect_uri, state)
            
            return AuthResult(success=True, redirect_url=auth_url)
        except Exception as e:
            return AuthResult(False, error_message=str(e))

    async def complete_oauth_flow(self, provider: str, code: str, redirect_uri: str,
                                ip_address: str = None, user_agent: str = None) -> AuthResult:
        """Complete OAuth flow and authenticate/create user"""
        if provider not in self.oauth_providers:
            return AuthResult(False, error_message=f"Provider {provider} not supported")
        
        try:
            oauth_provider = self.oauth_providers[provider]
            user_info = await oauth_provider.exchange_code_for_user_info(code, redirect_uri)
            
            if not user_info:
                return AuthResult(False, error_message="Failed to get user information from provider")
            
            async with AsyncSessionLocal() as db:
                # Check if user exists
                result = await db.execute(
                    select(User).where(User.email == user_info['email'])
                )
                user = result.scalar_one_or_none()
                
                if not user:
                    # Create pending signup for OAuth users
                    await self.create_signup_request(
                        email=user_info['email'],
                        display_name=user_info.get('name', user_info['email'].split('@')[0]),
                        provider=provider,
                        ip_address=ip_address
                    )
                    return AuthResult(False, error_message="Account pending admin approval")
                
                if not user.is_active or not user.is_approved:
                    return AuthResult(False, error_message="Account is inactive or pending approval")
                
                # Generate tokens
                access_token, refresh_token = create_tokens(user.id, user.email)
                
                # Store refresh token
                hashed_refresh = hash_refresh_token(refresh_token)
                refresh_token_obj = RefreshToken(
                    user_id=user.id,
                    token_hash=hashed_refresh,
                    expires_at=datetime.utcnow() + timedelta(days=30)
                )
                db.add(refresh_token_obj)
                
                # Log login attempt
                login_attempt = LoginAttempt(
                    user_id=user.id,
                    email=user.email,
                    ip_address=ip_address,
                    provider=provider,
                    success=True,
                    user_agent=user_agent
                )
                db.add(login_attempt)
                
                # Update last login
                user.last_login = datetime.utcnow()
                
                await db.commit()
                
                return AuthResult(
                    success=True,
                    user_id=user.id,
                    email=user.email,
                    access_token=access_token,
                    refresh_token=refresh_token
                )
                
        except Exception as e:
            return AuthResult(False, error_message=str(e))

    async def refresh_access_token(self, refresh_token: str) -> AuthResult:
        """Refresh access token using refresh token"""
        async with AsyncSessionLocal() as db:
            hashed_token = hash_refresh_token(refresh_token)
            
            # Find refresh token
            result = await db.execute(
                select(RefreshToken)
                .join(User, RefreshToken.user_id == User.id)
                .where(
                    and_(
                        RefreshToken.token_hash == hashed_token,
                        RefreshToken.expires_at > datetime.utcnow(),
                        RefreshToken.revoked == False,
                        User.is_active == True
                    )
                )
            )
            token_obj = result.scalar_one_or_none()
            
            if not token_obj:
                return AuthResult(False, error_message="Invalid or expired refresh token")
            
            # Get user
            result = await db.execute(
                select(User).where(User.id == token_obj.user_id)
            )
            user = result.scalar_one_or_none()
            
            if not user or not user.is_active:
                return AuthResult(False, error_message="User not found or inactive")
            
            # Generate new tokens
            access_token, new_refresh_token = create_tokens(user.id, user.email)
            
            # Revoke old refresh token
            token_obj.revoked = True
            
            # Store new refresh token
            new_hashed_refresh = hash_refresh_token(new_refresh_token)
            new_refresh_token_obj = RefreshToken(
                user_id=user.id,
                token_hash=new_hashed_refresh,
                expires_at=datetime.utcnow() + timedelta(days=30)
            )
            db.add(new_refresh_token_obj)
            
            await db.commit()
            
            return AuthResult(
                success=True,
                user_id=user.id,
                email=user.email,
                access_token=access_token,
                new_refresh_token=new_refresh_token
            )

    async def revoke_refresh_token(self, refresh_token: str) -> bool:
        """Revoke a refresh token"""
        async with AsyncSessionLocal() as db:
            hashed_token = hash_refresh_token(refresh_token)
            
            result = await db.execute(
                select(RefreshToken).where(RefreshToken.token_hash == hashed_token)
            )
            token_obj = result.scalar_one_or_none()
            
            if token_obj:
                token_obj.revoked = True
                await db.commit()
                return True
            
            return False

    async def get_user_details(self, user_id: uuid.UUID) -> Dict[str, Any]:
        """Get detailed user information including providers and login modes"""
        async with AsyncSessionLocal() as db:
            # Get user
            result = await db.execute(
                select(User).where(User.id == user_id)
            )
            user = result.scalar_one_or_none()
            
            if not user:
                raise ValueError("User not found")
            
            # Get provider links
            provider_result = await db.execute(
                select(AuthProviderLink).where(AuthProviderLink.user_id == user_id)
            )
            providers = provider_result.scalars().all()
            
            # Get recent login attempts
            login_result = await db.execute(
                select(LoginAttempt)
                .where(LoginAttempt.user_id == user_id)
                .order_by(LoginAttempt.timestamp.desc())
                .limit(10)
            )
            recent_logins = login_result.scalars().all()
            
            # Build login modes
            login_modes = {
                'password': any(p.provider_name == 'local_password' and p.is_enabled for p in providers),
                'otp': any(p.provider_name == 'email_otp' and p.is_enabled for p in providers),
                'google': any(p.provider_name == 'google' and p.is_enabled for p in providers),
                'azure': any(p.provider_name == 'azure' and p.is_enabled for p in providers),
                'github': any(p.provider_name == 'github' and p.is_enabled for p in providers),
            }
            
            return {
                'id': str(user.id),
                'email': user.email,
                'display_name': user.display_name,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'role': user.role,
                'is_active': user.is_active,
                'is_approved': user.is_approved,
                'is_admin': user.is_admin,
                'tenant_id': str(user.tenant_id) if user.tenant_id else None,
                'created_at': user.created_at.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'login_modes': login_modes,
                'providers': [
                    {
                        'id': str(p.id),
                        'provider_name': p.provider_name,
                        'external_id': p.external_id,
                        'is_enabled': p.is_enabled,
                        'linked_at': p.linked_at.isoformat()
                    } for p in providers
                ],
                'recent_logins': [
                    {
                        'provider': la.provider,
                        'success': la.success,
                        'ip_address': la.ip_address,
                        'timestamp': la.timestamp.isoformat()
                    } for la in recent_logins
                ]
            }

    async def update_user_status(self, user_id: uuid.UUID, is_active: bool, 
                               admin_user_id: uuid.UUID) -> bool:
        """Update user active status"""
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(User).where(User.id == user_id)
            )
            user = result.scalar_one_or_none()
            
            if not user:
                raise ValueError("User not found")
            
            user.is_active = is_active
            
            # Log audit event
            await self._log_audit(
                db, admin_user_id, 
                "enable_user" if is_active else "disable_user",
                "user", str(user_id),
                {"email": user.email, "is_active": is_active}
            )
            
            await db.commit()
            return True

    async def get_audit_logs(self, page: int = 1, limit: int = 50, 
                           action_type: str = None, target_type: str = None) -> Dict[str, Any]:
        """Get system audit logs with pagination"""
        async with AsyncSessionLocal() as db:
            query = select(AuditLog)
            
            if action_type:
                query = query.where(AuditLog.action_type == action_type)
            if target_type:
                query = query.where(AuditLog.target_type == target_type)
            
            # Get total count
            count_result = await db.execute(
                select(func.count(AuditLog.id)).select_from(query.subquery())
            )
            total = count_result.scalar()
            
            # Get paginated results
            result = await db.execute(
                query.order_by(AuditLog.timestamp.desc())
                .offset((page - 1) * limit)
                .limit(limit)
            )
            logs = result.scalars().all()
            
            return {
                "logs": [
                    {
                        'id': str(log.id),
                        'actor_user_id': str(log.actor_user_id) if log.actor_user_id else None,
                        'action_type': log.action_type,
                        'target_type': log.target_type,
                        'target_id': log.target_id,
                        'payload': log.payload,
                        'ip_address': log.ip_address,
                        'timestamp': log.timestamp.isoformat()
                    } for log in logs
                ],
                "total": total,
                "page": page,
                "limit": limit,
                "total_pages": (total + limit - 1) // limit
            }

    async def get_admin_stats(self) -> Dict[str, Any]:
        """Get system statistics for admin dashboard"""
        async with AsyncSessionLocal() as db:
            # Count users
            users_result = await db.execute(select(func.count(User.id)))
            total_users = users_result.scalar()
            
            active_users_result = await db.execute(
                select(func.count(User.id)).where(User.is_active == True)
            )
            active_users = active_users_result.scalar()
            
            # Count pending signups
            pending_result = await db.execute(
                select(func.count(PendingSignup.id)).where(PendingSignup.status == "pending")
            )
            pending_signups = pending_result.scalar()
            
            # Recent login attempts
            recent_logins_result = await db.execute(
                select(func.count(LoginAttempt.id))
                .where(LoginAttempt.timestamp > datetime.utcnow() - timedelta(days=7))
            )
            recent_logins = recent_logins_result.scalar()
            
            return {
                'total_users': total_users,
                'active_users': active_users,
                'pending_signups': pending_signups,
                'recent_logins_7d': recent_logins,
                'system_status': 'healthy'
            }

