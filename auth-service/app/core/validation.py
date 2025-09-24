"""
Input validation utilities
"""

import re
from typing import List, Optional
from datetime import datetime


def validate_email(email: str) -> Optional[str]:
    """
    Validate email format
    
    Args:
        email: Email address to validate
        
    Returns:
        Error message if invalid, None if valid
    """
    if not email:
        return "Email is required"
    
    # Basic email regex pattern
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(email_pattern, email):
        return "Invalid email format"
    
    if len(email) > 254:  # RFC 5321 limit
        return "Email address too long"
    
    return None


def validate_password(password: str) -> List[str]:
    """
    Validate password strength
    
    Args:
        password: Password to validate
        
    Returns:
        List of validation errors (empty if valid)
    """
    errors = []
    
    if not password:
        errors.append("Password is required")
        return errors
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    if len(password) > 128:
        errors.append("Password must be less than 128 characters")
    
    # Check for at least one lowercase letter
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    # Check for at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    # Check for at least one digit
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one number")
    
    # Check for at least one special character
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        errors.append("Password must contain at least one special character")
    
    # Check for common weak passwords
    weak_passwords = [
        "password", "123456", "password123", "admin", "qwerty",
        "letmein", "welcome", "monkey", "dragon", "master"
    ]
    
    if password.lower() in weak_passwords:
        errors.append("Password is too common")
    
    return errors


def validate_display_name(display_name: str) -> Optional[str]:
    """
    Validate display name
    
    Args:
        display_name: Display name to validate
        
    Returns:
        Error message if invalid, None if valid
    """
    if not display_name:
        return "Display name is required"
    
    if len(display_name.strip()) < 2:
        return "Display name must be at least 2 characters long"
    
    if len(display_name) > 100:
        return "Display name must be less than 100 characters"
    
    # Check for potentially harmful characters
    if re.search(r'[<>"\']', display_name):
        return "Display name contains invalid characters"
    
    return None


def validate_tenant_id(tenant_id: str) -> Optional[str]:
    """
    Validate tenant ID format
    
    Args:
        tenant_id: Tenant ID to validate
        
    Returns:
        Error message if invalid, None if valid
    """
    if not tenant_id:
        return "Tenant ID is required"
    
    # Should be alphanumeric with optional dashes and underscores
    if not re.match(r'^[a-zA-Z0-9_-]+$', tenant_id):
        return "Tenant ID can only contain letters, numbers, dashes and underscores"
    
    if len(tenant_id) < 3:
        return "Tenant ID must be at least 3 characters long"
    
    if len(tenant_id) > 50:
        return "Tenant ID must be less than 50 characters"
    
    return None


def validate_app_id(app_id: str) -> Optional[str]:
    """
    Validate application ID format
    
    Args:
        app_id: Application ID to validate
        
    Returns:
        Error message if invalid, None if valid
    """
    if not app_id:
        return "Application ID is required"
    
    # Should be alphanumeric with optional dashes and underscores
    if not re.match(r'^[a-zA-Z0-9_-]+$', app_id):
        return "Application ID can only contain letters, numbers, dashes and underscores"
    
    if len(app_id) < 3:
        return "Application ID must be at least 3 characters long"
    
    if len(app_id) > 50:
        return "Application ID must be less than 50 characters"
    
    return None


def validate_otp(otp: str) -> Optional[str]:
    """
    Validate OTP format
    
    Args:
        otp: OTP code to validate
        
    Returns:
        Error message if invalid, None if valid
    """
    if not otp:
        return "OTP is required"
    
    # Should be exactly 6 digits
    if not re.match(r'^\d{6}$', otp):
        return "OTP must be exactly 6 digits"
    
    return None


def sanitize_input(text: str, max_length: int = 1000) -> str:
    """
    Sanitize text input by removing potentially harmful characters
    
    Args:
        text: Text to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized text
    """
    if not text:
        return ""
    
    # Remove null bytes and control characters except newlines and tabs
    sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized.strip()