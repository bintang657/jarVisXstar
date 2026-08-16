from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import bcrypt

class CryptoArmor:
    @staticmethod
    def generate_key() -> str:
        return base64.urlsafe_b64encode(os.urandom(32)).decode()

    @staticmethod
    def encrypt_aes(data: str, key: str) -> str:
        f = Fernet(key.encode())
        return f.encrypt(data.encode()).decode()

    @staticmethod
    def decrypt_aes(encrypted: str, key: str) -> str:
        f = Fernet(key.encode())
        return f.decrypt(encrypted.encode()).decode()

    @staticmethod
    def hash_password(password: str) -> str:
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode(), salt).decode()

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        return bcrypt.checkpw(password.encode(), hashed.encode())