import os
import hashlib
from typing import Any, Optional
from cryptography.fernet import Fernet


class EncryptionManager:
    def __init__(self, log_manager) -> None:
        self.log_manager = log_manager
        self.key: Optional[bytes] = self.read_key()

    def read_key(self) -> Optional[bytes]:
        """
        Creates Fernet Key
        """
        key = os.getenv("FERNET_KEY")
        if not key:
            self.log_manager.write_log(
                error_message="Encryption key is missing or invalid."
            )
            return None
        try:
            return key.encode()
        except Exception as e:
            self.log_manager.write_log(
                error_message=f"Failed to encode key: {e}")
            return None

    def encrypt(self, data: list) -> list[Any]:
        """
        Encrypts Given Data using Fernet Encryption
        """
        if self.key is None:
            self.log_manager.write_log(
                error_message=f"Encryption key is missing or invalid.")
            raise ValueError("Encryption key is missing or invalid.")
        cipher = Fernet(self.key)
        return [cipher.encrypt(item.encode()) if isinstance(item, str) else item for item in data]

    def decrypt(self, data: list) -> list[Any]:
        """
        Decrypts Fernet Encrypted Data
        """
        if self.key is None:
            self.log_manager.write_log(
                error_message=f"Encryption key is missing or invalid.")
            raise ValueError("Encryption key is missing or invalid.")
        cipher = Fernet(self.key)
        return [cipher.decrypt(item).decode() if isinstance(item, bytes) else item for item in data]

    def generate_salt(self) -> bytes:
        """
        Generates and returns random 256-bit string as salt.
        """
        return os.urandom(32)

    def hash_password(
        self,
        password: str,
        salt: bytes,
        iterations=10000
    ) -> bytes:
        """
        Hashes Given Password
        """
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
