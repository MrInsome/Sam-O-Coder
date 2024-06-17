import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class Encryptor:
    def __init__(self, password: str):
        self.backend = default_backend()
        self.password = password

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode('utf-8'))

    def encrypt(self, plaintext: str) -> (bytes, bytes):
        salt = os.urandom(16)
        key = self._derive_key(self.password, salt)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        hmac = HMAC(key, hashes.SHA256(), backend=self.backend)
        hmac.update(iv + ciphertext)
        hmac_value = hmac.finalize()
        return salt, salt + iv + ciphertext + hmac_value


class Decryptor:
    def __init__(self, password: str, salt: bytes):
        self.backend = default_backend()
        self.password = password
        self.salt = salt
        self.key = self._derive_key(password, salt)

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode('utf-8'))

    def decrypt(self, ciphertext: bytes) -> str:
        iv = ciphertext[16:32]
        hmac_value = ciphertext[-32:]
        encrypted_message = ciphertext[32:-32]
        hmac = HMAC(self.key, hashes.SHA256(), backend=self.backend)
        hmac.update(iv + encrypted_message)
        hmac.verify(hmac_value)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(encrypted_message) + decryptor.finalize()
        return plaintext.decode('utf-8')


if __name__ == "__main__":
    plaintext = input("Enter the message to encrypt: ")
    password = input("Enter the password for encryption: ")

    encryptor = Encryptor(password)
    salt, encrypted = encryptor.encrypt(plaintext)
    print(f"Password: {password}")
    print(f"Salt: {salt}")
    print(f"Encrypted: {encrypted}")

    password = input("Enter the password for decryption: ")

    decryptor = Decryptor(password, salt)
    decrypted = decryptor.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
