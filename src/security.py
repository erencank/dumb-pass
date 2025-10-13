import uuid
from datetime import datetime, timedelta, timezone

import jwt
from fastapi.security import OAuth2PasswordBearer

from src.core.config import get_settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


def create_jwt(data: dict, secret: str, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret, algorithm=get_settings().algorithm)


def create_access_token(user_id: uuid.UUID, device_id: uuid.UUID) -> str:
    return create_jwt(
        data={"user_id": str(user_id), "device_id": str(device_id), "type": "access"},
        secret=get_settings().secret_key,
        expires_delta=timedelta(minutes=get_settings().access_token_expiration_minutes),
    )


def create_challenge_token(user_id: uuid.UUID, device_id: uuid.UUID, nonce: str) -> str:
    return create_jwt(
        data={"user_id": str(user_id), "device_id": str(device_id), "nonce": nonce},
        secret=get_settings().challenge_secret_key,
        expires_delta=timedelta(minutes=get_settings().challenge_token_expiration_minutes),
    )
