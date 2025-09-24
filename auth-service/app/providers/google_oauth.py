"""
Google OAuth2 authentication provider
"""

from typing import Dict, Any, Optional
import uuid
import httpx
import jwt
from urllib.parse import urlencode

from .base import (
    AuthProvider, 
    ProviderType, 
    ProviderStartResult, 
    ProviderCompleteResult, 
    NormalizedUser,
    LinkAccountResult
)


class GoogleOAuthProvider(AuthProvider):
    """Google OAuth2 authentication provider"""
    
    GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
    GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
    
    @property
    def provider_id(self) -> str:
        return "google"
    
    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.GOOGLE_OAUTH
    
    @property
    def display_name(self) -> str:
        return "Google"
    
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
        """Initiate Google OAuth flow"""
        redirect_uri = kwargs.get("redirect_uri", self.config.get("redirect_uri"))
        state = kwargs.get("state")  # Anti-CSRF state parameter
        
        if not redirect_uri:
            return ProviderStartResult(
                success=False,
                error_message="Redirect URI is required"
            )
        
        # Build authorization URL
        params = {
            "client_id": self.config["client_id"],
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",  # Request refresh token
        }
        
        if state:
            params["state"] = state
        
        auth_url = f"{self.GOOGLE_AUTH_URL}?{urlencode(params)}"
        
        return ProviderStartResult(
            success=True,
            redirect_url=auth_url
        )
    
    async def complete_auth(self, **kwargs) -> ProviderCompleteResult:
        """Complete Google OAuth flow using authorization code"""
        code = kwargs.get("code")
        redirect_uri = kwargs.get("redirect_uri", self.config.get("redirect_uri"))
        
        if not code:
            return ProviderCompleteResult(
                success=False,
                error_message="Authorization code is required"
            )
        
        try:
            # Exchange code for tokens
            token_data = await self._exchange_code_for_tokens(code, redirect_uri)
            if not token_data:
                return ProviderCompleteResult(
                    success=False,
                    error_message="Failed to exchange authorization code"
                )
            
            # Get user info from Google
            user_info = await self._get_user_info(token_data["access_token"])
            if not user_info:
                return ProviderCompleteResult(
                    success=False,
                    error_message="Failed to get user information from Google"
                )
            
            # Normalize user data
            normalized_user = NormalizedUser(
                email=user_info["email"].lower(),
                display_name=user_info.get("name", user_info["email"]),
                external_id=user_info["id"],
                email_verified=user_info.get("verified_email", False),
                avatar_url=user_info.get("picture"),
                provider_metadata={
                    "google_id": user_info["id"],
                    "access_token": token_data["access_token"],
                    "refresh_token": token_data.get("refresh_token"),
                    "token_expires_at": token_data.get("expires_in"),
                    "raw_profile": user_info
                }
            )
            
            # Check if this is a new user (requires approval) or existing user
            requires_approval = kwargs.get("is_new_user", False)
            
            return ProviderCompleteResult(
                success=True,
                user_data=normalized_user,
                requires_approval=requires_approval
            )
        
        except Exception as e:
            return ProviderCompleteResult(
                success=False,
                error_message=f"Google OAuth error: {str(e)}"
            )
    
    async def link_account(self, user_id: uuid.UUID, **kwargs) -> LinkAccountResult:
        """Link Google account to existing user"""
        code = kwargs.get("code")
        redirect_uri = kwargs.get("redirect_uri", self.config.get("redirect_uri"))
        
        if not code:
            return LinkAccountResult(
                success=False,
                error_message="Authorization code is required"
            )
        
        try:
            # Exchange code for tokens
            token_data = await self._exchange_code_for_tokens(code, redirect_uri)
            user_info = await self._get_user_info(token_data["access_token"])
            
            link_data = {
                "external_id": user_info["id"],
                "email": user_info["email"],
                "access_token": token_data["access_token"],
                "refresh_token": token_data.get("refresh_token"),
                "profile_data": user_info
            }
            
            return LinkAccountResult(
                success=True,
                link_data=link_data
            )
        
        except Exception as e:
            return LinkAccountResult(
                success=False,
                error_message=f"Failed to link Google account: {str(e)}"
            )
    
    async def _exchange_code_for_tokens(self, code: str, redirect_uri: str) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for access/refresh tokens"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.GOOGLE_TOKEN_URL,
                data={
                    "client_id": self.config["client_id"],
                    "client_secret": self.config["client_secret"],
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": redirect_uri,
                }
            )
            
            if response.status_code == 200:
                return response.json()
            return None
    
    async def _get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        """Get user information from Google using access token"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                self.GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if response.status_code == 200:
                return response.json()
            return None
    
    async def refresh_credentials(self, user_id: uuid.UUID, **kwargs) -> bool:
        """Refresh Google OAuth tokens"""
        refresh_token = kwargs.get("refresh_token")
        
        if not refresh_token:
            return False
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.GOOGLE_TOKEN_URL,
                    data={
                        "client_id": self.config["client_id"],
                        "client_secret": self.config["client_secret"],
                        "refresh_token": refresh_token,
                        "grant_type": "refresh_token",
                    }
                )
                
                if response.status_code == 200:
                    # Update stored tokens in database
                    # This would be implemented in the service layer
                    return True
                
        except Exception:
            pass
        
        return False
    
    def validate_config(self) -> list[str]:
        """Validate Google OAuth configuration"""
        errors = []
        
        if not self.config.get("client_id"):
            errors.append("Google client_id is required")
        
        if not self.config.get("client_secret"):
            errors.append("Google client_secret is required")
        
        if not self.config.get("redirect_uri"):
            errors.append("Google redirect_uri is required")
        
        return errors