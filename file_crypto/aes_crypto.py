import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Generate key from password using PBKDF2
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# AES Encryption (Now using AES-GCM for better security)
def aes_encrypt(file_path, password):
    try:
        salt = os.urandom(16)  # Generate a new salt for key derivation
        key = derive_key(password, salt)
        iv = os.urandom(12)  # AES-GCM requires a 12-byte IV

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(file_path, "rb") as f:
            plaintext = f.read()

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Save salt, IV, and authentication tag along with the ciphertext
        with open(file_path, "wb") as f:
            f.write(salt + iv + encryptor.tag + ciphertext)

        return file_path
    except Exception as e:
        print(f"Encryption failed: {e}")
        return None

# AES Decryption
def aes_decrypt(file_path, password):
    try:
        with open(file_path, "rb") as f:
            content = f.read()

        salt = content[:16]
        iv = content[16:28]
        tag = content[28:44]
        ciphertext = content[44:]

        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        with open(file_path, "wb") as f:
            f.write(plaintext)

        return file_path
    except Exception as e:
        print(f"Decryption failed: {e}")
        return False  # Returns False when the decryption fails (wrong password)
