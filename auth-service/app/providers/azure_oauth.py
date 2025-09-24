"""
Microsoft Azure AD OAuth2 provider implementation
"""

import httpx
from typing import Dict, Any, Optional
from urllib.parse import urlencode
import logging

from app.providers.base import AuthProvider, ProviderType, ProviderStartResult, ProviderCompleteResult, NormalizedUser, LinkAccountResult
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class AzureOAuthProvider(AuthProvider):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.tenant_id = self.config.get("tenant_id", "common")
        self.client_id = self.config.get("client_id")
        self.client_secret = self.config.get("client_secret") 
        self.redirect_uri = self.config.get("redirect_uri")
        self._enabled = bool(self.client_id and self.client_secret and self.redirect_uri)

    @property
    def provider_id(self) -> str:
        return "azure"

    @property
    def provider_id(self) -> str:
        return "azure"

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.AZURE_OAUTH

    @property
    def display_name(self) -> str:
        return "Microsoft Azure AD"

    @property
    def supports_signup(self) -> bool:
        return True

    @property
    def supports_login(self) -> bool:
        return True

    @property
    def supports_linking(self) -> bool:
        return True

    def configure(self, config: Dict[str, Any]) -> None:
        """Configure the Azure provider with client credentials"""
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.redirect_uri = config.get("redirect_uri")
        self.tenant_id = config.get("tenant_id", "common")
        self._enabled = bool(self.client_id and self.client_secret and self.redirect_uri)

    def validate_config(self) -> Dict[str, Any]:
        """Validate provider configuration"""
        errors = []
        
        if not self.client_id:
            errors.append("Azure Client ID is required")
        if not self.client_secret:
            errors.append("Azure Client Secret is required")
        if not self.redirect_uri:
            errors.append("Redirect URI is required")
        
        return {
            "is_valid": len(errors) == 0,
            "errors": errors,
            "enabled": self._enabled
        }

    async def start_auth(self, **kwargs) -> ProviderStartResult:
        """Start Azure OAuth2 flow"""
        if not self._enabled:
            return ProviderStartResult(
                success=False,
                error="Azure OAuth provider not configured"
            )

        state = kwargs.get("state", "")
        scopes = kwargs.get("scopes", ["openid", "profile", "email"])
        
        # Azure AD OAuth2 authorization endpoint
        auth_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/authorize"
        
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "response_mode": "query"
        }

        authorization_url = f"{auth_url}?{urlencode(params)}"
        
        return ProviderStartResult(
            success=True,
            redirect_url=authorization_url,
            state=state
        )

    async def complete_auth(self, **kwargs) -> ProviderCompleteResult:
        """Complete Azure OAuth2 flow"""
        if not self._enabled:
            return ProviderCompleteResult(
                success=False,
                error="Azure OAuth provider not configured"
            )

        code = kwargs.get("code")
        if not code:
            return ProviderCompleteResult(
                success=False,
                error="Authorization code not provided"
            )

        try:
            # Exchange authorization code for access token
            token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
            
            token_data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": self.redirect_uri,
                "scope": "openid profile email"
            }

            async with httpx.AsyncClient() as client:
                token_response = await client.post(token_url, data=token_data)
                token_response.raise_for_status()
                tokens = token_response.json()

            access_token = tokens.get("access_token")
            if not access_token:
                return ProviderCompleteResult(
                    success=False,
                    error="Failed to obtain access token"
                )

            # Get user profile from Microsoft Graph API
            profile_url = "https://graph.microsoft.com/v1.0/me"
            headers = {"Authorization": f"Bearer {access_token}"}

            async with httpx.AsyncClient() as client:
                profile_response = await client.get(profile_url, headers=headers)
                profile_response.raise_for_status()
                profile_data = profile_response.json()

            # Normalize user data
            user_data = NormalizedUser(
                external_id=profile_data.get("id"),
                email=profile_data.get("mail") or profile_data.get("userPrincipalName"),
                display_name=profile_data.get("displayName", ""),
                provider_metadata={
                    "azure_user_id": profile_data.get("id"),
                    "tenant_id": self.tenant_id,
                    "job_title": profile_data.get("jobTitle"),
                    "department": profile_data.get("department"),
                    "office_location": profile_data.get("officeLocation"),
                    "verified": True  # Azure accounts are always verified
                }
            )

            return ProviderCompleteResult(
                success=True,
                user=user_data,
                tokens=tokens
            )

        except httpx.HTTPStatusError as e:
            logger.error(f"Azure OAuth HTTP error: {e}")
            return ProviderCompleteResult(
                success=False,
                error=f"Azure authentication failed: {e.response.status_code}"
            )
        except Exception as e:
            logger.error(f"Azure OAuth error: {e}")
            return ProviderCompleteResult(
                success=False,
                error="Azure authentication failed"
            )

    def get_login_url(self, **kwargs) -> str:
        """Get Azure login URL for frontend"""
        if not self._enabled:
            return ""
        
        state = kwargs.get("state", "")
        auth_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/authorize"
        
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": "openid profile email",
            "state": state,
            "response_mode": "query"
        }

        return f"{auth_url}?{urlencode(params)}"

    async def link_account(self, user_id: uuid.UUID, **kwargs) -> LinkAccountResult:
        """Link Azure account to existing user"""
        code = kwargs.get("code")
        if not code:
            return LinkAccountResult(
                success=False,
                error_message="Authorization code is required"
            )

        try:
            # Exchange code for tokens
            token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
            
            token_data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": self.redirect_uri,
                "scope": "openid profile email"
            }

            async with httpx.AsyncClient() as client:
                token_response = await client.post(token_url, data=token_data)
                token_response.raise_for_status()
                tokens = token_response.json()

            access_token = tokens.get("access_token")
            if not access_token:
                return LinkAccountResult(
                    success=False,
                    error_message="Failed to obtain access token"
                )

            # Get user profile
            profile_url = "https://graph.microsoft.com/v1.0/me"
            headers = {"Authorization": f"Bearer {access_token}"}

            async with httpx.AsyncClient() as client:
                profile_response = await client.get(profile_url, headers=headers)
                profile_response.raise_for_status()
                profile_data = profile_response.json()

            link_data = {
                "external_id": profile_data.get("id"),
                "email": profile_data.get("mail") or profile_data.get("userPrincipalName"),
                "access_token": access_token,
                "profile_data": profile_data
            }

            return LinkAccountResult(
                success=True,
                link_data=link_data
            )

        except Exception as e:
            logger.error(f"Azure account linking error: {e}")
            return LinkAccountResult(
                success=False,
                error_message="Failed to link Azure account"
            )