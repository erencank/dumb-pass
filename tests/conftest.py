import os
from typing import Generator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, StaticPool, create_engine

from src.core import config
from src.core.config import Settings
from src.db import get_session
from src.main import app


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
