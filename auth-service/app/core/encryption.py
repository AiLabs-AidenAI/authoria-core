"""
Encryption utilities for sensitive data
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
from typing import str


class EncryptionManager:
    def __init__(self, key: str = None):
        if key is None:
            key = os.getenv("ENCRYPTION_KEY")
            if not key:
                raise ValueError("ENCRYPTION_KEY environment variable is required")
        
        # Derive a Fernet key from the provided key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'stable_salt_for_auth_service',  # In production, use random salt per encrypted value
            iterations=100000,
        )
        key_bytes = base64.urlsafe_b64encode(kdf.derive(key.encode()))
        self.fernet = Fernet(key_bytes)
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt a plaintext string"""
        if not plaintext:
            return plaintext
        return self.fernet.encrypt(plaintext.encode()).decode()
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a ciphertext string"""
        if not ciphertext:
            return ciphertext
        return self.fernet.decrypt(ciphertext.encode()).decode()


# Global encryption manager instance
_encryption_manager = None

def get_encryption_manager() -> EncryptionManager:
    global _encryption_manager
    if _encryption_manager is None:
        _encryption_manager = EncryptionManager()
    return _encryption_manager


async def encrypt_value(value: str) -> str:
    """Encrypt a value using the global encryption manager"""
    return get_encryption_manager().encrypt(value)


async def decrypt_value(value: str) -> str:
    """Decrypt a value using the global encryption manager"""
    return get_encryption_manager().decrypt(value)