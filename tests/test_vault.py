import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import status

from src.crypto import OAEP_PADDING, decrypt_with_aes_gcm, encrypt_with_aes_gcm
from tests.conftest import UserDeviceFixture


def test_create_and_get_vault_items(authenticated_client, user_and_device: UserDeviceFixture) -> None:
    """
    Tests the "happy path": an authenticated user can create a vault item
    and then retrieve it.
    """
    # --- 1. SIMULATE CLIENT-SIDE ENCRYPTION OF A VAULT ITEM ---
    _item_key = os.urandom(32)  # A unique symmetric key for this item
    secret_data = b'{"username": "testuser", "password": "supersecret"}'
    encrypted_blob = encrypt_with_aes_gcm(secret_data, _item_key)
    _encrypted_item_key = user_and_device.user_public_key.encrypt(_item_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    # The client would send these two encrypted blobs to the server.
    # We encode them as base64 strings to send them in a JSON payload.

    blob = base64.b64encode(encrypted_blob).decode("utf-8")
    item_key = base64.b64encode(_encrypted_item_key).decode("utf-8")

    payload = {"blob": blob, "item_key": item_key}

    # --- 2. CREATE THE VAULT ITEM VIA API ---
    response = authenticated_client.post("/vault/", json=payload)
    assert response.status_code == status.HTTP_201_CREATED

    created_item = response.json()
    assert "id" in created_item
    # Verify the server returns the same encrypted data it received
    assert created_item["blob"] == blob
    assert created_item["item_key"] == item_key

    # --- 3. RETRIEVE ALL VAULT ITEMS FOR THE USER ---
    response = authenticated_client.get("/vault/")
    assert response.status_code == status.HTTP_200_OK

    items = response.json()
    assert len(items) == 1
    assert items[0]["id"] == created_item["id"]
    assert items[0]["blob"] == created_item["blob"]

    # --- 4. DECRYPT AND VALIDATE VAULT ITEM ---
    encrypted_item_key_bytes = base64.b64decode(items[0]["item_key"])
    encrypted_blob_bytes = base64.b64decode(items[0]["blob"])

    decrypted_item_key = user_and_device.user_private_key.decrypt(encrypted_item_key_bytes, OAEP_PADDING)
    decrypted_blob = decrypt_with_aes_gcm(encrypted_blob_bytes, decrypted_item_key)

    assert decrypted_blob == secret_data
