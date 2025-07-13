import argon2
from typing import Any
from getpass import getuser
from keyring import get_password
from cryptography.fernet import Fernet


class EncryptionManager:
    """
    Manages encryption and decryption of data.
    """

    def __init__(self, log_manager: Any) -> None:
        """
        Initialize the EncryptionManager with a log manager object.
        Args:
            log_manager: The log manager object, expected to have a 'log' method.
        """
        self.log_manager = log_manager
        self.key: bytes | None = self.read_key()
        self.ph = argon2.PasswordHasher(
            time_cost=2, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16
        )

    def read_key(self) -> bytes | None:
        """
        Creates Fernet Key
        Returns:
            bytes | None: Fernet Key is returned if found, else None.
        """
        key = get_password("fernet_key", getuser())
        if not key:
            self.log_manager.log("Warning", "Fernet Encryption Key Could Not Be Found.")
            return None
        try:
            return key.encode()
        except Exception as error:
            self.log_manager.log("Error", f"Failed to encode key: {error}")
            return None

    def encrypt(self, data: list[int | str]) -> list[int | bytes]:
        """
        Encrypts Given Data using Fernet Encryption
        Args:
            data (list): Data to be encrypted.
        Returns:
            list[Any]: Encrypted data.
        """
        if self.key is None:
            self.log_manager.log("Error", f"Encryption key is missing or invalid.")
            raise ValueError("Encryption key is missing or invalid.")
        cipher = Fernet(self.key)
        return [
            cipher.encrypt(item.encode()) if isinstance(item, str) else item
            for item in data
        ]

    def decrypt(self, data: list[str]) -> list[str]:
        """
        Decrypts Given Data using Fernet Encryption
        Args:
            data (list): Data to be decrypted.
        Returns:
            list[str]: Decrypted data.
        """
        if self.key is None:
            self.log_manager.log("Error", "Encryption key is missing or invalid.")
            raise ValueError("Encryption key is missing or invalid.")
        cipher = Fernet(self.key)
        return [cipher.decrypt(item.encode()).decode() for item in data]

    def hash_password(self, password: str) -> str:
        """
        Hash password using Argon2.
        Args:
            password (str): Password to password_hash.
        """
        try:
            return self.ph.hash(password)
        except Exception as e:
            self.log_manager.log("Error", f"Argon2 hashing failed: {e}")
            raise

    def verify_password(self, password: str, password_hash: str) -> bool:
        """
        Verify a password against an Argon2id password_hash.
        """
        try:
            self.ph.verify(password_hash, password)
            return True
        except argon2.exceptions.VerifyMismatchError:
            self.log_manager.log(
                "Warning", "Password verification failed: Passwords do not match."
            )
            return False
        except Exception as e:
            self.log_manager.log("Error", f"Argon2 verification failed: {e}")
            return False
