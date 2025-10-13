import base64
import uuid

import jwt
from fastapi import status

from src.core.config import get_settings
from src.crypto import sign_data
from tests.auth_utils import _create_payload
from tests.conftest import UserDeviceFixture


def test_register_user(client) -> None:
    payload = _create_payload()

    payload_dict = payload.user.model_dump()

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


def test_login_challenge(client, user_and_device: UserDeviceFixture) -> None:
    payload = {"email": user_and_device.user.email, "device_id": str(user_and_device.device.id)}

    response = client.post("auth/token/challenge", json=payload)
    assert response.status_code == status.HTTP_200_OK

    response_data = response.json()
    challenge_token = response_data["challenge_token"]

    settings = get_settings()
    challenge_payload = jwt.decode(challenge_token, algorithms=[settings.algorithm], options={"verify_signature": False})
    nonce = challenge_payload.get("nonce")
    assert nonce is not None

    signature = sign_data(user_and_device.device_private_key, nonce.encode())

    token_payload = {
        "challenge_token": challenge_token,
        "signature": base64.b64encode(signature).decode("ascii"),  # Send signature as a B64 in JSON
    }
    response = client.post("/auth/token", json=token_payload)
    assert response.status_code == status.HTTP_200_OK

    token_response_data = response.json()
    access_token = token_response_data["access_token"]

    response = client.get("/auth/users/me", headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == status.HTTP_200_OK

    user_response_data = response.json()
    assert user_response_data["email"] == user_and_device.user.email


def test_invalid_login_challenge(client, user_and_device: UserDeviceFixture) -> None:
    payload = {"email": user_and_device.user.email, "device_id": str(uuid.uuid4())}

    response = client.post("auth/token/challenge", json=payload)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    payload = {"email": str("randommail@mail.com"), "device_id": str(user_and_device.device.id)}

    response = client.post("auth/token/challenge", json=payload)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_invalid_response_login_challenge(client, user_and_device: UserDeviceFixture) -> None:
    payload = {"email": user_and_device.user.email, "device_id": str(user_and_device.device.id)}

    response = client.post("auth/token/challenge", json=payload)
    assert response.status_code == status.HTTP_200_OK

    response_data = response.json()
    challenge_token = response_data["challenge_token"]

    settings = get_settings()
    challenge_payload = jwt.decode(challenge_token, algorithms=[settings.algorithm], options={"verify_signature": False})
    nonce = challenge_payload.get("nonce")
    assert nonce is not None

    token_payload = {
        "challenge_token": challenge_token,
        "signature": base64.b64encode(b"blablabla").decode("ascii"),
    }
    response = client.post("/auth/token", json=token_payload)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    signature = sign_data(user_and_device.device_private_key, nonce.encode())

    token_payload = {
        "challenge_token": jwt.encode({"blabla": "oof"}, "blabla", get_settings().algorithm),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    response = client.post("/auth/token", json=token_payload)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
