import os
from cryptography.fernet import Fernet

class EncryptionManager:
    def __init__(self):
        self.key = self.read_key()


    # Creates Fernet Key
    def read_key(self):
        key = os.getenv("FERNET_KEY")
        if not key:
            raise Exception("Encryption key is missing or invalid.")
        return key


    # Encrypts Given Data using Fernet Encryption
    def encrypt(self, data):
        cipher = Fernet(self.key)
        return [cipher.encrypt(item.encode()) if isinstance(item, str) else item for item in data]
    

    # Decrypts Fernet Encrypted Data
    def decrypt(self, data):
        cipher = Fernet(self.key)
        return [cipher.decrypt(item).decode() if isinstance(item, bytes) else item for item in data]