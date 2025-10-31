import base64
import os
from typing import Generator

import jwt
import pytest
from fastapi import FastAPI, status
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, StaticPool, create_engine

from src.core import config
from src.core.config import Settings, get_settings
from src.crypto import sign_data
from src.db import get_session
from src.main import app
from src.models import Device, User, Vault, VaultItem
from tests.utils import UserDeviceFixture, _create_payload, create_vault_item


@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session

    SQLModel.metadata.drop_all(engine)

    if os.path.exists("./test.db"):
        os.remove("./test.db")


@pytest.fixture(name="test_app")
def test_app_fixture(session: Session) -> Generator[FastAPI, FastAPI, None]:
    def override_get_session() -> Session:
        return session

    app.dependency_overrides[get_session] = override_get_session
    yield app
    app.dependency_overrides.clear()


@pytest.fixture
def test_settings() -> Generator[Settings, Settings, None]:
    "Makes a replacement settings object that can be modified by the tests which get reset afterwards"
    original_settings = config._settings
    test_settings = Settings()  # type: ignore[call-arg]
    config._settings = test_settings
    yield test_settings
    config._settings = original_settings


@pytest.fixture
def client(test_app: FastAPI) -> Generator[TestClient, TestClient, None]:
    client = TestClient(test_app, raise_server_exceptions=False)

    yield client


@pytest.fixture(name="user_and_device")
def registered_user_and_device(session: Session) -> UserDeviceFixture:
    """
    Fixture that creates a user and their first device, adds them to the
    database, and returns the model instances.
    """
    payload = _create_payload()
    created_user = payload.user

    user = User.model_validate(created_user.model_dump())
    device = Device(
        device_name=created_user.device_name,
        public_key=payload.user.device_public_key,
        encrypted_private_key_blob=created_user.device_encrypted_private_key_blob,
        encrypted_wrapping_key=created_user.device_encrypted_wrapping_key,
        signature=None,
        user=user,
    )

    default_vault = Vault(name="Default", owner=user)

    session.add(user)
    session.add(device)
    session.add(default_vault)
    session.commit()
    session.refresh(user)
    session.refresh(device)

    user.default_vault_id = default_vault.id
    session.add(user)
    session.commit()
    session.refresh(user)

    return UserDeviceFixture(
        user=user,
        device=device,
        master_password=payload.master_password,
        user_private_key=payload.user_private_key,
        user_public_key=payload.user_public_key,
        device_private_key=payload.device_private_key,
        device_public_key=payload.device_public_key,
    )


@pytest.fixture(name="user_vault_item")
def user_vault_item_fixture(user_and_device: UserDeviceFixture, session: Session) -> VaultItem:
    data = {"email": "foo@bar.com", "password": "foobar123"}
    item = create_vault_item(user_device=user_and_device, data=data)

    session.add(item)
    session.commit()
    session.refresh(item)

    return item


@pytest.fixture(name="authenticated_client")
def authenticated_client_fixture(
    client: TestClient, user_and_device: UserDeviceFixture
) -> TestClient:
    """
    Fixture that provides an authenticated client. It logs in the user
    created by the `user_and_device` fixture and sets the Authorization header.
    """
    # Step 1: Get the challenge
    challenge_payload = {
        "email": user_and_device.user.email,
        "device_id": str(user_and_device.device.id),
    }
    response = client.post("/auth/token/challenge", json=challenge_payload)
    assert response.status_code == status.HTTP_200_OK
    challenge_token = response.json()["challenge_token"]

    # Step 2: Solve the challenge
    settings = get_settings()
    challenge_payload = jwt.decode(
        challenge_token,
        settings.challenge_secret_key,
        algorithms=[settings.algorithm],
    )
    nonce = challenge_payload.get("nonce", "")
    signature = sign_data(user_and_device.device_private_key, nonce.encode())

    # Step 3: Get the access token
    token_payload = {
        "challenge_token": challenge_token,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    response = client.post("/auth/token", json=token_payload)
    assert response.status_code == status.HTTP_200_OK
    access_token = response.json()["access_token"]

    # Step 4: Set the authorization header for subsequent requests
    client.headers["Authorization"] = f"Bearer {access_token}"

    return client
