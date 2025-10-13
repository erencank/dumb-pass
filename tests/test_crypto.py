import os

import pytest
from cryptography.exceptions import InvalidKey, InvalidTag

from src.crypto import decrypt_with_aes_gcm, derive_encryption_key, encrypt_with_aes_gcm, verify_derived_encryption_key


def test_derived_encryption_key() -> None:
    password = "a-very-strong-password-123!"
    salt = os.urandom(16).hex()

    derived_encryption_key = derive_encryption_key(password, salt)

    assert verify_derived_encryption_key(password, salt, derived_encryption_key)

    with pytest.raises(InvalidKey):
        verify_derived_encryption_key(password, salt, b"blablabla")

    with pytest.raises(InvalidKey):
        verify_derived_encryption_key("another random password", salt, derived_encryption_key)

    with pytest.raises(InvalidKey):
        verify_derived_encryption_key(password, os.urandom(16).hex(), derived_encryption_key)


def test_aes_gcm_symmetrical_encryption() -> None:
    key = os.urandom(32)  # AES-256 key
    original_data = b"test data please dont figure out"

    encrypted_blob = encrypt_with_aes_gcm(original_data, key)

    decrypted_data = decrypt_with_aes_gcm(encrypted_blob, key)
    assert decrypted_data == original_data
    assert decrypted_data is not encrypted_blob

    wrong_key = os.urandom(32)
    with pytest.raises(InvalidTag):
        decrypt_with_aes_gcm(encrypted_blob, wrong_key)

    tampered_blob = bytearray(encrypted_blob)
    tampered_blob[-1] ^= 1  # Flip the last bit of the last byte
    with pytest.raises(InvalidTag):
        decrypt_with_aes_gcm(bytes(tampered_blob), key)
