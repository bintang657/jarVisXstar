import os
import hashlib
import secrets
from cryptography.fernet import Fernet
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

class GodCryptoArmor:
    def __init__(self, master_key=None):
        if master_key is None:
            master_key = Fernet.generate_key()
        self.fernet = Fernet(master_key)
        self.argon2 = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32)

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return self.fernet.encrypt(data)

    def decrypt(self, encrypted_data):
        return self.fernet.decrypt(encrypted_data)

    def hash_password(self, password):
        return self.argon2.hash(password)

    def verify_password(self, password, hashed):
        try:
            self.argon2.verify(hashed, password)
            return True
        except VerifyMismatchError:
            return False

    def generate_secure_token(self, length=32):
        return secrets.token_urlsafe(length)

    def generate_api_key(self, prefix='sk_'):
        return prefix + secrets.token_urlsafe(48)