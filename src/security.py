import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session

from src.core.config import get_settings
from src.db import get_session
from src.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: Annotated[Session, Depends(get_session)],
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        settings = get_settings()
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        if not payload.get("type") == "access":
            raise credentials_exception
        user_id: str = payload.get("user_id")
        if user_id is None:
            raise credentials_exception
    except (jwt.PyJWTError, TypeError):
        raise credentials_exception

    user = session.get(User, uuid.UUID(user_id))
    if user is None:
        raise credentials_exception
    return user


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
