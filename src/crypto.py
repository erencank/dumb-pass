import os
from typing import cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return password_hash.hash(password)


# --- Asymmetric Cryptography (RSA) ---
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


# --- Symmetric Encryption (AES-GCM) ---
def encrypt_with_aes_gcm(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(12)  # 96-bit IV for GCM
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext


def decrypt_with_aes_gcm(encrypted_data: bytes, key: bytes) -> bytes:
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# --- Key Derivation (DEK) ---
def _create_kdf(salt: str) -> Argon2id:
    return Argon2id(
        salt=salt.encode(),
        length=32,
        iterations=1,
        lanes=4,
        memory_cost=64 * 1024,
        ad=None,
        secret=None,
    )


def derive_encryption_key(password: str, salt: str) -> bytes:
    kdf = _create_kdf(salt)
    derived_encryption_key = kdf.derive(password.encode())
    return derived_encryption_key


def verify_derived_encryption_key(password: str, salt: str, key: bytes) -> bool:
    kdf = _create_kdf(salt)
    kdf.verify(password.encode(), key)
    return True


# --- Other ---
def sign_data(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """Signs data with the given private key using PSS padding."""
    return private_key.sign(
        data,
        algorithm=hashes.SHA256(),
        padding=PSS_PADDING,
    )


def verify_signature(public_key_bytes: bytes, signature: bytes, data: bytes) -> bool:
    try:
        public_key: rsa.RSAPublicKey = cast(
            rsa.RSAPublicKey, serialization.load_pem_public_key(public_key_bytes)
        )
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("verify_signature only supports RSAPublicKey type")
        public_key.verify(
            signature,
            data,
            algorithm=hashes.SHA256(),
            padding=PSS_PADDING,
        )
        return True
    except Exception:
        # This will catch invalid signatures, key formats, etc.
        return False


OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
)
PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(algorithm=hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
)
