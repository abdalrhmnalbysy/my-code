import os
import pyotp
import shutil
import getpass
from datetime import datetime
from cryptography.hazmat.primitives import serialization, padding as sym_padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.backends import default_backend

# ------------- Key rotation function -------------
def rotate_old_keys():
    """If old keys exist, move them to a timestamped folder before generating new ones."""
    if os.path.exists("keys/private_key.pem") and os.path.exists("keys/public_key.pem"):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        archive_dir = f"keys/old_keys/{timestamp}"
        os.makedirs(archive_dir, exist_ok=True)
        shutil.move("keys/private_key.pem", f"{archive_dir}/private_key.pem")
        shutil.move("keys/public_key.pem", f"{archive_dir}/public_key.pem")
        print(f"🔁 Old keys moved to: {archive_dir}")
    else:
        print("ℹ️ No previous keys found for rotation.")

# ------------- Generate RSA keys with rotation -------------
def generate_rsa_keys(password: bytes):
    rotate_old_keys()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    with open("keys/private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        ))

    with open("keys/public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("✅ New RSA keys generated and saved in keys/")
    print("🔐 Private key saved to: keys/private_key.pem")
    print("🔓 Public key saved to: keys/public_key.pem")

    return private_key, public_key

# ------------- Helper functions -------------
def load_private_key(password: bytes):
    with open("keys/private_key.pem", "rb") as f:
        private_pem = f.read()
    try:
        return serialization.load_pem_private_key(private_pem, password=password, backend=default_backend())
    except ValueError:
        print("❌ Incorrect password. Please make sure you entered it correctly.")
        exit(1)

def load_public_key():
    with open("keys/public_key.pem", "rb") as f:
        public_pem = f.read()
    return serialization.load_pem_public_key(public_pem, backend=default_backend())

def generate_aes_key_iv():
    key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)   # 128-bit IV for AES CBC
    return key, iv

def encrypt_aes(data: bytes, key: bytes, iv: bytes):
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_aes(encrypted_data: bytes, key: bytes, iv: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def encrypt_rsa(data: bytes, public_key):
    return public_key.encrypt(
        data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_rsa(encrypted_data: bytes, private_key):
    return private_key.decrypt(
        encrypted_data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ------------- Main program -------------
def main():
    # 🔐 Prompt user to enter password securely
    password = getpass.getpass("🔐 Enter the password for the private key: ").encode()

    # Ensure folders exist
    os.makedirs("keys", exist_ok=True)
    os.makedirs("encrypted", exist_ok=True)

    # Generate RSA keys with rotation of old keys
    private_key, public_key = generate_rsa_keys(password)

    # Read data from files
    with open("test_data/fake_message.txt", "rb") as f:
        message_data = f.read()

    with open("test_data/fake_data.json", "rb") as f:
        json_data = f.read()

    # Generate AES key and IV
    aes_key, iv = generate_aes_key_iv()

    # Encrypt data with AES
    encrypted_message = encrypt_aes(message_data, aes_key, iv)
    encrypted_json = encrypt_aes(json_data, aes_key, iv)

    # Encrypt AES key with RSA public key
    encrypted_aes_key = encrypt_rsa(aes_key, public_key)

    # Save encrypted files
    with open("encrypted/encrypted_message.bin", "wb") as f:
        f.write(encrypted_message)

    with open("encrypted/encrypted_data.bin", "wb") as f:
        f.write(encrypted_json)

    with open("encrypted/encrypted_key.bin", "wb") as f:
        f.write(encrypted_aes_key)

    with open("encrypted/iv.bin", "wb") as f:
        f.write(iv)

    print("✅ Files encrypted and saved in encrypted/")

    # Start decryption test
    print("🔓 Starting decryption test...")

    # Load private key to decrypt AES key
    private_key_loaded = load_private_key(password)

    # Decrypt AES key
    decrypted_aes_key = decrypt_rsa(encrypted_aes_key, private_key_loaded)

    # Decrypt files
    decrypted_message = decrypt_aes(encrypted_message, decrypted_aes_key, iv)
    decrypted_json = decrypt_aes(encrypted_json, decrypted_aes_key, iv)

    # Save decrypted files
    with open("decrypted_message.txt", "wb") as f:
        f.write(decrypted_message)

    with open("decrypted_data.json", "wb") as f:
        f.write(decrypted_json)

    # Check if decrypted data matches original
    if decrypted_message == message_data:
        print("✅ Message decrypted successfully and matches original.")
    else:
        print("❌ Error decrypting message!")

    if decrypted_json == json_data:
        print("✅ JSON data decrypted successfully and matches original.")
    else:
        print("❌ Error decrypting JSON data!")

if __name__ == "__main__":
    main()