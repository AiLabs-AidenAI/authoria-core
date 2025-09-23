"""
Local email/password authentication provider
"""

from typing import Dict, Any, Optional
import uuid
import argon2
from argon2.exceptions import VerifyMismatchError

from .base import (
    AuthProvider, 
    ProviderType, 
    ProviderStartResult, 
    ProviderCompleteResult, 
    NormalizedUser,
    LinkAccountResult
)
from ..core.security import hash_password, verify_password
from ..core.validation import validate_password, validate_email


class LocalPasswordProvider(AuthProvider):
    """Email and password authentication provider"""
    
    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.LOCAL_PASSWORD
    
    @property
    def display_name(self) -> str:
        return "Email & Password"
    
    @property
    def supports_signup(self) -> bool:
        return True
    
    @property
    def supports_login(self) -> bool:
        return True
    
    @property
    def supports_linking(self) -> bool:
        return True
    
    async def start_auth(self, **kwargs) -> ProviderStartResult:
        """
        For password auth, no separate "start" step - validation happens in complete_auth
        This is mainly used for signup to validate password strength
        """
        email = kwargs.get("email")
        password = kwargs.get("password")
        
        if not email or not password:
            return ProviderStartResult(
                success=False,
                error_message="Email and password are required"
            )
        
        # Validate email format
        email_error = validate_email(email)
        if email_error:
            return ProviderStartResult(
                success=False,
                error_message=email_error
            )
        
        # Validate password strength
        password_errors = validate_password(password)
        if password_errors:
            return ProviderStartResult(
                success=False,
                error_message="; ".join(password_errors)
            )
        
        return ProviderStartResult(
            success=True,
            session_data={"validated": True}
        )
    
    async def complete_auth(self, **kwargs) -> ProviderCompleteResult:
        """
        Complete password authentication
        For signup: create normalized user data
        For login: verify credentials
        """
        email = kwargs.get("email")
        password = kwargs.get("password")
        display_name = kwargs.get("display_name")
        is_signup = kwargs.get("is_signup", False)
        stored_password_hash = kwargs.get("password_hash")  # For login verification
        
        if not email or not password:
            return ProviderCompleteResult(
                success=False,
                error_message="Email and password are required"
            )
        
        if is_signup:
            # Signup flow - create new user data
            if not display_name:
                return ProviderCompleteResult(
                    success=False,
                    error_message="Display name is required for signup"
                )
            
            # Re-validate (should have been done in start_auth)
            start_result = await self.start_auth(email=email, password=password)
            if not start_result.success:
                return ProviderCompleteResult(
                    success=False,
                    error_message=start_result.error_message
                )
            
            # Hash password for storage
            password_hash = hash_password(password)
            
            normalized_user = NormalizedUser(
                email=email.lower().strip(),
                display_name=display_name.strip(),
                email_verified=False,  # Email verification can be added later
                provider_metadata={"password_hash": password_hash}
            )
            
            return ProviderCompleteResult(
                success=True,
                user_data=normalized_user,
                requires_approval=True  # Local signups require admin approval
            )
        
        else:
            # Login flow - verify credentials
            if not stored_password_hash:
                return ProviderCompleteResult(
                    success=False,
                    error_message="Invalid credentials"
                )
            
            if not verify_password(password, stored_password_hash):
                return ProviderCompleteResult(
                    success=False,
                    error_message="Invalid credentials"
                )
            
            normalized_user = NormalizedUser(
                email=email.lower().strip(),
                display_name="",  # Will be filled from database
                email_verified=True  # Assume verified if they can log in
            )
            
            return ProviderCompleteResult(
                success=True,
                user_data=normalized_user
            )
    
    async def link_account(self, user_id: uuid.UUID, **kwargs) -> LinkAccountResult:
        """Link password authentication to an existing user account"""
        password = kwargs.get("password")
        
        if not password:
            return LinkAccountResult(
                success=False,
                error_message="Password is required"
            )
        
        # Validate password strength
        password_errors = validate_password(password)
        if password_errors:
            return LinkAccountResult(
                success=False,
                error_message="; ".join(password_errors)
            )
        
        # Hash password
        password_hash = hash_password(password)
        
        return LinkAccountResult(
            success=True,
            link_data={"password_hash": password_hash}
        )
    
    def validate_config(self) -> list[str]:
        """Validate provider configuration"""
        errors = []
        
        # Check if password hashing is available
        try:
            import argon2
        except ImportError:
            errors.append("argon2-cffi library is required for password hashing")
        
        return errors