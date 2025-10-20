import base64
import os

from fastapi import status

from src.crypto import encrypt_with_aes_gcm


def test_create_and_get_vault_items(authenticated_client, user_and_device) -> None:
    """
    Tests the "happy path": an authenticated user can create a vault item
    and then retrieve it.
    """
    # --- 1. SIMULATE CLIENT-SIDE ENCRYPTION OF A VAULT ITEM ---
    _item_key = os.urandom(32)  # A unique symmetric key for this item
    secret_data = b'{"username": "testuser", "password": "supersecret"}'
    encrypted_blob = encrypt_with_aes_gcm(secret_data, _item_key)

    # The client would send these two encrypted blobs to the server.
    # We encode them as base64 strings to send them in a JSON payload.

    blob = base64.b64encode(encrypted_blob).decode("utf-8")
    item_key = base64.b64encode(_item_key).decode("utf-8")

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
