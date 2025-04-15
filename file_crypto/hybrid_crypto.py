import os
import shutil
from .aes_crypto import aes_encrypt, aes_decrypt
from .rsa_crypto import rsa_encrypt_file, rsa_decrypt_file, generate_rsa_keys
from .blowfish_crypto import blowfish_encrypt, blowfish_decrypt

# Define the keys directory correctly
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS_DIR = os.path.join(BASE_DIR, "keys")

# Ensure the directory exists
os.makedirs(KEYS_DIR, exist_ok=True)

# Define key paths
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")


def hybrid_encrypt(file_path, hybrid_choice, password):
    """
    Hybrid encryption based on user selection.
    Sequentially encrypts the file without overwriting incorrectly.
    """
    try:
        print(f"🔹 Hybrid Encryption Selected: {hybrid_choice}")

        temp_file = file_path  # Keep track of the changing file name
        
        # Ensure RSA keys exist if needed
        if hybrid_choice in ["1", "3", "4", "6"]:  # RSA is involved
            if not os.path.exists(PUBLIC_KEY_PATH) or not os.path.exists(PRIVATE_KEY_PATH):
                generate_rsa_keys(KEYS_DIR)

        # Encryption Steps
        if hybrid_choice == "1":  # AES → RSA
            aes_encrypt(temp_file, password)
            rsa_encrypt_file(temp_file, PUBLIC_KEY_PATH)
        elif hybrid_choice == "2":  # AES → Blowfish
            aes_encrypt(temp_file, password)
            blowfish_encrypt(temp_file, password)
        elif hybrid_choice == "3":  # RSA → Blowfish
            rsa_encrypt_file(temp_file, PUBLIC_KEY_PATH)
            blowfish_encrypt(temp_file, password)
        elif hybrid_choice == "4":  # AES → RSA → Blowfish
            aes_encrypt(temp_file, password)
            rsa_encrypt_file(temp_file, PUBLIC_KEY_PATH)
            blowfish_encrypt(temp_file, password)
        elif hybrid_choice == "5":  # Blowfish → AES
            blowfish_encrypt(temp_file, password)
            aes_encrypt(temp_file, password)
        elif hybrid_choice == "6":  # Blowfish → RSA
            blowfish_encrypt(temp_file, password)
            rsa_encrypt_file(temp_file, PUBLIC_KEY_PATH)

        print(f"✅ File successfully encrypted using Hybrid method {hybrid_choice}")
        return True

    except Exception as e:
        print(f"❌ Error in hybrid_encrypt: {e}")
        return False


def hybrid_decrypt(file_path, hybrid_choice, password):
    """
    Hybrid decryption based on user selection.
    The decryption order is **REVERSED** compared to encryption.
    """
    try:
        print(f"🔹 Hybrid Decryption Selected: {hybrid_choice}")

        temp_file = file_path  # Keep track of the changing file name

        # Ensure RSA keys exist if required
        if hybrid_choice in ["1", "3", "4", "6"]:  # RSA is involved
            if not os.path.exists(PRIVATE_KEY_PATH):
                print(f"❌ Error: Private key not found at {PRIVATE_KEY_PATH}")
                return False  # Prevent decryption without RSA keys

        # Decryption Steps (Reverse Order)
        if hybrid_choice == "1":  # RSA → AES
            rsa_decrypt_file(temp_file, PRIVATE_KEY_PATH)
            aes_decrypt(temp_file, password)
        elif hybrid_choice == "2":  # Blowfish → AES
            blowfish_decrypt(temp_file, password)
            aes_decrypt(temp_file, password)
        elif hybrid_choice == "3":  # Blowfish → RSA
            blowfish_decrypt(temp_file, password)
            rsa_decrypt_file(temp_file, PRIVATE_KEY_PATH)
        elif hybrid_choice == "4":  # Blowfish → RSA → AES
            blowfish_decrypt(temp_file, password)
            rsa_decrypt_file(temp_file, PRIVATE_KEY_PATH)
            aes_decrypt(temp_file, password)
        elif hybrid_choice == "5":  # AES → Blowfish
            aes_decrypt(temp_file, password)
            blowfish_decrypt(temp_file, password)
        elif hybrid_choice == "6":  # RSA → Blowfish
            rsa_decrypt_file(temp_file, PRIVATE_KEY_PATH)
            blowfish_decrypt(temp_file, password)

        print(f"✅ File successfully decrypted using Hybrid method {hybrid_choice}")
        return True

    except Exception as e:
        print(f"❌ Error in hybrid_decrypt: {e}")
        return False
