import base64
import os
from datetime import UTC, datetime, timedelta

from fastapi import status

from src.crypto import decrypt_with_aes_gcm, encrypt_with_aes_gcm
from src.models import VaultItem
from tests.utils import UserDeviceFixture


def test_create_share_link(
    authenticated_client, user_and_device: UserDeviceFixture, user_vault_item: VaultItem
) -> None:
    start_datetime = datetime.now(UTC) + timedelta(hours=24)
    _link_key = os.urandom(32)
    secret_data = b'{"username": "testuser", "password": "supersecret"}'
    encrypted_blob = encrypt_with_aes_gcm(secret_data, _link_key)

    blob = base64.b64encode(encrypted_blob).decode("utf-8")
    link_key = base64.b64encode(_link_key).decode("utf-8")
    payload = {
        "encrypted_blob": blob,
        "expires_in_hours": 2,
        "vault_item_id": str(user_vault_item.id),
    }
    response = authenticated_client.post("/links/", json=payload)

    assert response.status_code == status.HTTP_201_CREATED
    created_link = response.json()

    share_link = f"www.dumb-pass.com/share/{created_link['link_id']}#{link_key}"

    response = authenticated_client.get(f"/links/{created_link['link_id']}")
    assert response.status_code == status.HTTP_200_OK

    retrieved_link = response.json()
    url_link_key = base64.b64decode(share_link.split("#")[-1])
    contents = base64.b64decode(retrieved_link["contents"])
    decrypted_blob = decrypt_with_aes_gcm(contents, url_link_key)

    assert decrypted_blob == secret_data

    end_datetime = datetime.now(UTC) + timedelta(hours=24)
    expiration_datetime = datetime.fromtimestamp(retrieved_link["expiration_timestamp"], UTC)

    assert start_datetime > expiration_datetime < end_datetime

    # Check if doing a GET for the vault item returns the public link
    vault_id = str(user_and_device.user.default_vault_id)
    response = authenticated_client.get(f"/items/by-vault/{vault_id}")
    assert response.status_code == status.HTTP_200_OK

    items = response.json()
    assert len(items) == 1
    item = items[0]
    assert len(item["public_links"]) == 1
    vault_link = item["public_links"][0]

    assert vault_link["current_views"] == 1
    assert vault_link["max_views"] is None
    assert expiration_datetime == datetime.fromtimestamp(vault_link["expiration_timestamp"], UTC)
