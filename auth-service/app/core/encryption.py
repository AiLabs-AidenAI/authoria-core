"""
Encryption utilities for sensitive data
"""

import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from app.core.config import get_settings

settings = get_settings()

def get_encryption_key() -> bytes:
    """Get or generate encryption key for sensitive data"""
    # Use SECRET_KEY to derive encryption key
    password = settings.SECRET_KEY.encode()
    salt = b'auth_service_salt'  # In production, use a proper random salt
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def get_cipher():
    """Get Fernet cipher instance"""
    return Fernet(get_encryption_key())

async def encrypt_value(value: str) -> str:
    """Encrypt a string value"""
    if not value:
        return value
    
    cipher = get_cipher()
    encrypted = cipher.encrypt(value.encode())
    return base64.urlsafe_b64encode(encrypted).decode()

async def decrypt_value(encrypted_value: str) -> str:
    """Decrypt an encrypted string value"""
    if not encrypted_value:
        return encrypted_value
    
    try:
        cipher = get_cipher()
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_value.encode())
        decrypted = cipher.decrypt(encrypted_bytes)
        return decrypted.decode()
    except Exception:
        # If decryption fails, return as-is (might be unencrypted legacy data)
        return encrypted_value