import os
import hashlib
from typing import Optional
from cryptography.fernet import Fernet


class EncryptionManager:
    def __init__(self, log_manager) -> None:
        self.log_manager = log_manager
        self.key = self.read_key()

    def read_key(self) -> Optional[bytes]:
        """
        Creates Fernet Key
        """
        key = os.getenv("FERNET")
        if not key:
            self.log_manager.write_log(
                error_message="Encryption key is missing or invalid."
            )
            return None
        return key

    def encrypt(self, data: list):
        """
        Encrypts Given Data using Fernet Encryption
        """
        cipher = Fernet(self.key)
        return [cipher.encrypt(item.encode()) if isinstance(item, str) else item for item in data]

    def decrypt(self, data: list):
        """
        Decrypts Fernet Encrypted Data
        """
        cipher = Fernet(self.key)
        return [cipher.decrypt(item).decode() if isinstance(item, bytes) else item for item in data]

    def generate_salt(self):
        """
        Generates salt
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
