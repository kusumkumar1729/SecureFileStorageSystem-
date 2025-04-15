import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1

# Constants for key and IV sizes
RSA_KEY_SIZE = 256  # Encrypted AES key size (RSA-2048)
IV_SIZE = 12  # AES IV size
AES_KEY_SIZE = 32  # AES key must be 32 bytes (256 bits)

def generate_rsa_keys(keys_dir="keys"):
    """Generate RSA key pair if not already present."""
    os.makedirs(keys_dir, exist_ok=True)
    private_key_path = os.path.join(keys_dir, "private_key.pem")
    public_key_path = os.path.join(keys_dir, "public_key.pem")

    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        return public_key_path, private_key_path  # Use existing keys

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_key_path, "wb") as private_file:
        private_file.write(private_pem)

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_key_path, "wb") as public_file:
        public_file.write(public_pem)

    return public_key_path, private_key_path

def rsa_encrypt_file(file_path, public_key_path):
    """Encrypt a file using AES and encrypt the AES key with RSA."""
    try:
        if not os.path.exists(public_key_path):
            raise FileNotFoundError(f"Public key not found: {public_key_path}")

        # Generate AES key and IV
        aes_key = os.urandom(AES_KEY_SIZE)
        aesgcm = AESGCM(aes_key)
        iv = os.urandom(IV_SIZE)

        # Read file data
        with open(file_path, "rb") as f:
            data = f.read()

        # Encrypt file content
        encrypted_data = aesgcm.encrypt(iv, data, None)

        # Load RSA public key
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        # Encrypt AES key with RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            OAEP(
                mgf=MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Save encrypted file (overwrite original file)
        with open(file_path, "wb") as f:
            f.write(encrypted_aes_key + iv + encrypted_data)

        print(f"File encrypted successfully: {file_path}")
        return file_path
    except Exception as e:
        print(f"Error in rsa_encrypt_file: {e}")
        return None

def rsa_decrypt_file(encrypted_file_path, private_key_path):
    """Decrypt a file using RSA to retrieve AES key, then decrypt with AES."""
    try:
        if not os.path.exists(private_key_path):
            raise FileNotFoundError(f"Private key not found: {private_key_path}")
        if not os.path.exists(encrypted_file_path):
            raise FileNotFoundError(f"Encrypted file not found: {encrypted_file_path}")

        # Read encrypted file
        with open(encrypted_file_path, "rb") as f:
            content = f.read()

        # Ensure file has enough data for RSA key, IV, and encrypted content
        if len(content) < RSA_KEY_SIZE + IV_SIZE:
            raise ValueError("Encrypted file is corrupted or incomplete.")

        # Extract RSA encrypted AES key, IV, and encrypted data
        encrypted_aes_key = content[:RSA_KEY_SIZE]
        iv = content[RSA_KEY_SIZE:RSA_KEY_SIZE + IV_SIZE]
        encrypted_data = content[RSA_KEY_SIZE + IV_SIZE:]

        # Load RSA private key
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        # Decrypt AES key with RSA
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            OAEP(
                mgf=MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Ensure AES key is 32 bytes
        if len(aes_key) != AES_KEY_SIZE:
            raise ValueError(f"Decrypted AES key has incorrect size: {len(aes_key)} bytes")

        # Decrypt data with AES
        aesgcm = AESGCM(aes_key)
        decrypted_data = aesgcm.decrypt(iv, encrypted_data, None)

        # Save decrypted file (overwrite original file)
        with open(encrypted_file_path, "wb") as f:
            f.write(decrypted_data)

        print(f"File decrypted successfully: {encrypted_file_path}")
    
        return encrypted_file_path
        
    except Exception as e:
        print(f"Error in rsa_decrypt_file: {e}")
        return None
