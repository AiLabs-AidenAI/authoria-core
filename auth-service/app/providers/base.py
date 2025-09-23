"""
Base authentication provider interface and common types
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from enum import Enum
import uuid


class ProviderType(str, Enum):
    LOCAL_PASSWORD = "local_password"
    EMAIL_OTP = "email_otp"
    GOOGLE_OAUTH = "google"
    AZURE_OIDC = "azure"
    GITHUB_OAUTH = "github"
    SAML = "saml"


@dataclass
class ProviderStartResult:
    """Result from initiating authentication with a provider"""
    success: bool
    redirect_url: Optional[str] = None  # For OAuth flows
    session_data: Optional[Dict[str, Any]] = None  # Temporary session data
    error_message: Optional[str] = None
    requires_verification: bool = False  # For OTP flows


@dataclass
class ProviderCompleteResult:
    """Result from completing authentication with a provider"""
    success: bool
    user_data: Optional['NormalizedUser'] = None
    error_message: Optional[str] = None
    requires_approval: bool = False  # New user needs admin approval
    metadata: Optional[Dict[str, Any]] = None  # Provider-specific metadata


@dataclass
class NormalizedUser:
    """Standardized user data from any provider"""
    email: str
    display_name: str
    external_id: Optional[str] = None  # Provider's user ID
    email_verified: bool = False
    avatar_url: Optional[str] = None
    provider_metadata: Optional[Dict[str, Any]] = None


@dataclass
class LinkAccountResult:
    """Result from linking a provider to an existing user account"""
    success: bool
    link_data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None


class AuthProvider(ABC):
    """Abstract base class for authentication providers"""
    
    def __init__(self, provider_id: str, config: Dict[str, Any]):
        self.provider_id = provider_id
        self.config = config
    
    @property
    @abstractmethod
    def provider_type(self) -> ProviderType:
        """Return the type of this provider"""
        pass
    
    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable name for this provider"""
        pass
    
    @property
    @abstractmethod
    def supports_signup(self) -> bool:
        """Whether this provider can be used for new user registration"""
        pass
    
    @property
    @abstractmethod
    def supports_login(self) -> bool:
        """Whether this provider can be used for existing user login"""
        pass
    
    @property
    @abstractmethod
    def supports_linking(self) -> bool:
        """Whether this provider can be linked to existing accounts"""
        pass
    
    @abstractmethod
    async def start_auth(self, **kwargs) -> ProviderStartResult:
        """
        Initiate authentication flow with this provider
        
        Args:
            **kwargs: Provider-specific parameters (email, redirect_uri, etc.)
            
        Returns:
            ProviderStartResult with next steps for the client
        """
        pass
    
    @abstractmethod
    async def complete_auth(self, **kwargs) -> ProviderCompleteResult:
        """
        Complete authentication flow and return normalized user data
        
        Args:
            **kwargs: Provider-specific completion data (code, state, otp, etc.)
            
        Returns:
            ProviderCompleteResult with user data or error
        """
        pass
    
    @abstractmethod
    async def link_account(self, user_id: uuid.UUID, **kwargs) -> LinkAccountResult:
        """
        Link this provider to an existing user account
        
        Args:
            user_id: The user to link this provider to
            **kwargs: Provider-specific linking parameters
            
        Returns:
            LinkAccountResult indicating success/failure
        """
        pass
    
    async def unlink_account(self, user_id: uuid.UUID) -> bool:
        """
        Unlink this provider from a user account
        
        Args:
            user_id: The user to unlink this provider from
            
        Returns:
            True if successfully unlinked, False otherwise
        """
        # Default implementation - can be overridden
        return True
    
    async def refresh_credentials(self, user_id: uuid.UUID, **kwargs) -> bool:
        """
        Refresh provider credentials (e.g., OAuth tokens)
        
        Args:
            user_id: The user whose credentials to refresh
            **kwargs: Provider-specific refresh parameters
            
        Returns:
            True if successfully refreshed, False otherwise
        """
        # Default implementation - can be overridden
        return True
    
    def validate_config(self) -> List[str]:
        """
        Validate provider configuration
        
        Returns:
            List of validation errors (empty if valid)
        """
        return []


class ProviderRegistry:
    """Registry for managing authentication providers"""
    
    def __init__(self):
        self._providers: Dict[str, AuthProvider] = {}
    
    def register(self, provider: AuthProvider) -> None:
        """Register a new authentication provider"""
        self._providers[provider.provider_id] = provider
    
    def unregister(self, provider_id: str) -> None:
        """Unregister an authentication provider"""
        self._providers.pop(provider_id, None)
    
    def get(self, provider_id: str) -> Optional[AuthProvider]:
        """Get a provider by ID"""
        return self._providers.get(provider_id)
    
    def list_all(self) -> List[AuthProvider]:
        """Get all registered providers"""
        return list(self._providers.values())
    
    def list_by_type(self, provider_type: ProviderType) -> List[AuthProvider]:
        """Get all providers of a specific type"""
        return [p for p in self._providers.values() if p.provider_type == provider_type]
    
    def get_enabled(self) -> List[AuthProvider]:
        """Get all enabled providers (based on configuration)"""
        return [p for p in self._providers.values() if self._is_provider_enabled(p)]
    
    def _is_provider_enabled(self, provider: AuthProvider) -> bool:
        """Check if a provider is properly configured and enabled"""
        errors = provider.validate_config()
        return len(errors) == 0


# Global provider registry instance
provider_registry = ProviderRegistry()