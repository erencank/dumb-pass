import base64
import os
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import status

from src.crypto import encrypt_with_aes_gcm, generate_rsa_key_pair
from src.models import UserCreate


def test_register_user(client) -> None:
    payload = _create_payload()

    payload_dict = payload.model_dump()

    # 3. Manually encode all 'bytes' fields to Base64 strings for JSON compatibility
    # These are the fields in your UserCreate model that are of type `bytes`
    binary_fields = [
        "public_key",
        "encrypted_private_key",
        "device_public_key",
        "device_encrypted_private_key_blob",
        "device_encrypted_wrapping_key",
    ]

    for field in binary_fields:
        if field in payload_dict and isinstance(payload_dict[field], bytes):
            # Encode bytes to a Base64 string (e.g., b'abc' -> 'YWJj')
            payload_dict[field] = base64.b64encode(payload_dict[field]).decode("ascii")

    response = client.post("auth/register", json=payload_dict)
    assert response.status_code == status.HTTP_201_CREATED

    response_data = response.json()
    assert response_data["status"] == "success"


def _create_payload() -> UserCreate:
    # A. Generate a fake master password and salt
    master_password = "a-very-strong-password-123!"
    master_password_salt = os.urandom(16).hex()

    # Should be derived from password and salt
    derived_encryption_key = os.urandom(32)

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
    encrypted_wrapping_key = user_public_key.encrypt(wrapping_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    # F. Serialize public keys to bytes for the payload
    user_public_key_pem = user_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    device_public_key_pem = device_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    registration_payload = UserCreate(
        email=f"testuser_{uuid.uuid4().hex}@example.com",
        # In a real client, this hash would be generated from the master password.
        # For the test, we can send a placeholder since the server just stores it.
        master_password_hash="placeholder_hash_from_client",
        master_password_salt=master_password_salt,
        public_key=user_public_key_pem,
        encrypted_private_key=encrypted_user_private_key,
        device_name="Test Device",
        device_public_key=device_public_key_pem,
        device_encrypted_private_key_blob=encrypted_device_private_key_blob,
        device_encrypted_wrapping_key=encrypted_wrapping_key,
    )
    return registration_payload
