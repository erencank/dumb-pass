import os
from typing import Generator, NamedTuple

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, StaticPool, create_engine

from src.core import config
from src.core.config import Settings
from src.db import get_session
from src.main import app
from src.models import Device, User
from tests.auth_utils import _create_payload


@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
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
def client(test_app) -> Generator[TestClient, TestClient, None]:
    client = TestClient(test_app, raise_server_exceptions=False)

    yield client


class UserDeviceFixture(NamedTuple):
    user: User
    device: Device
    master_password: str
    user_private_key: rsa.RSAPrivateKey
    user_public_key: rsa.RSAPublicKey
    device_private_key: rsa.RSAPrivateKey
    device_public_key: rsa.RSAPublicKey


@pytest.fixture(name="user_and_device")
def registered_user_and_device(session: Session) -> UserDeviceFixture:
    """
    Fixture that creates a user and their first device, adds them to the
    database, and returns the model instances.
    """
    payload = _create_payload()
    created_user = payload.user

    user = User.model_validate(created_user)
    device = Device(
        device_name=created_user.device_name,
        public_key=payload.user.device_public_key,
        encrypted_private_key_blob=created_user.device_encrypted_private_key_blob,
        encrypted_wrapping_key=created_user.device_encrypted_wrapping_key,
        signature=None,
        user=user,
    )

    session.add(user)
    session.add(device)
    session.commit()
    session.refresh(user)
    session.refresh(device)

    return UserDeviceFixture(
        user=user,
        device=device,
        master_password=payload.master_password,
        user_private_key=payload.user_private_key,
        user_public_key=payload.user_public_key,
        device_private_key=payload.device_private_key,
        device_public_key=payload.device_public_key,
    )
