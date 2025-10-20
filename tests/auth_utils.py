import base64
import os
import uuid
from typing import NamedTuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from src.crypto import OAEP_PADDING, derive_encryption_key, encrypt_with_aes_gcm, generate_rsa_key_pair
from src.models import UserCreate


class TestUserPayload(NamedTuple):
    user: UserCreate
    master_password: str
    user_private_key: rsa.RSAPrivateKey
    user_public_key: rsa.RSAPublicKey
    device_private_key: rsa.RSAPrivateKey
    device_public_key: rsa.RSAPublicKey


def _create_payload() -> TestUserPayload:
    # A. Generate a fake master password and salt
    master_password = "a-very-strong-password-123!"
    master_password_salt = os.urandom(16).hex()

    derived_encryption_key = derive_encryption_key(master_password_salt, master_password)

    # B. Generate the user's master key pair
    user_private_key, user_public_key = generate_rsa_key_pair()

    # C. Encrypt the user's private key with the derived key
    user_private_key_pem = user_private_key.private_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()
    )
    encrypted_user_private_key = encrypt_with_aes_gcm(user_private_key_pem, derived_encryption_key)

    # D. Generate the first device's key pair
    device_private_key, device_public_key = generate_rsa_key_pair()
    device_private_key_pem = device_private_key.private_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()
    )

    # E.1. Generate a new, single-use AES key (the "wrapping key")
    wrapping_key = os.urandom(32)

    # E.2. Encrypt the large data (device private key) with the AES wrapping key
    encrypted_device_private_key_blob = encrypt_with_aes_gcm(device_private_key_pem, wrapping_key)

    # E.3. Encrypt the small AES wrapping key with the USER's PUBLIC RSA key
    encrypted_wrapping_key = user_public_key.encrypt(wrapping_key, OAEP_PADDING)

    # F. Serialize public keys to bytes for the payload
    user_public_key_pem = user_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    device_public_key_pem = device_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    registration_payload = UserCreate(
        email=f"testuser_{uuid.uuid4().hex}@example.com",
        # In a real client, this hash would be generated from the master password.
        # For the test, we can send a placeholder since the server just stores it.
        master_password_hash="placeholder_hash_from_client",
        master_password_salt=master_password_salt,
        public_key=base64.b64encode(user_public_key_pem).decode("ascii"),
        encrypted_private_key=base64.b64encode(encrypted_user_private_key).decode("ascii"),
        device_name="Test Device",
        device_public_key=base64.b64encode(device_public_key_pem).decode("ascii"),
        device_encrypted_private_key_blob=base64.b64encode(encrypted_device_private_key_blob).decode("ascii"),
        device_encrypted_wrapping_key=base64.b64encode(encrypted_wrapping_key).decode("ascii"),
    )
    return TestUserPayload(
        user=registration_payload,
        master_password=master_password,
        user_private_key=user_private_key,
        user_public_key=user_public_key,
        device_private_key=device_private_key,
        device_public_key=device_public_key,
    )
