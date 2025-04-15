import os
import Crypto
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad

def blowfish_encrypt(file_path, key):
    key = key.encode('utf-8').ljust(56)[:56]  # Blowfish allows keys up to 56 bytes
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    iv = cipher.iv  # Initialization vector

    with open(file_path, "rb") as f:
        plaintext = f.read()

    ciphertext = cipher.encrypt(pad(plaintext, Blowfish.block_size))
    encrypted_file_path = file_path

    with open(encrypted_file_path, "wb") as f:
        f.write(iv + ciphertext)

    return encrypted_file_path

def blowfish_decrypt(encrypted_file_path, key):
    key = key.encode('utf-8').ljust(56)[:56]

    with open(encrypted_file_path, "rb") as f:
        content = f.read()

    iv = content[:8]  # Blowfish IV is 8 bytes
    ciphertext = content[8:]

    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)
    decrypted_file_path = encrypted_file_path

    with open(decrypted_file_path, "wb") as f:
        f.write(plaintext)

    return decrypted_file_path
