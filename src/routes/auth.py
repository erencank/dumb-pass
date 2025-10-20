import os
import uuid
from typing import Annotated

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from src.core.config import get_settings
from src.crypto import verify_signature
from src.db import get_session
from src.models import ChallengeRequest, ChallengeResponse, Device, TokenRequest, TokenResponse, User, UserCreate, UserCreateResponse
from src.security import create_access_token, create_challenge_token, get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get("/users/me")
def read_users_me(current_user: Annotated[User, Depends(get_current_user)]):
    """
    A protected endpoint that returns the current authenticated user's details.
    """
    return {"email": current_user.email}


@router.post("/register", response_model=UserCreateResponse, status_code=status.HTTP_201_CREATED)
def register(request: UserCreate, session: Annotated[Session, Depends(get_session)]):
    existing_user = session.exec(select(User).where(User.email == request.email)).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    user = User.model_validate(request.model_dump())

    device = Device(
        device_name=request.device_name,
        public_key=request.device_public_key,
        encrypted_private_key_blob=request.device_encrypted_private_key_blob,
        encrypted_wrapping_key=request.device_encrypted_wrapping_key,
        signature=None,  # First device has no signature
        user=user,  # Link the device to the new user
    )

    session.add(user)
    session.add(device)
    session.commit()

    session.refresh(user)
    session.refresh(device)

    return UserCreateResponse(status="success", user_id=user.id, device_id=device.id)


@router.post("/token/challenge", response_model=ChallengeResponse)
def get_login_challenge(request: ChallengeRequest, session: Annotated[Session, Depends(get_session)]):
    """
    Step 1 of login.
    Client provides email and device ID.
    Server returns the user's salt and a unique, short-lived challenge.
    """

    user = session.exec(select(User).where(User.email == request.email)).first()
    if not user:
        # We return a plain 401 since we don't want to give more info than needed
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    device = session.exec(select(Device).where(Device.id == request.device_id, Device.user_id == user.id)).first()
    if not device:
        # We return a plain 401 since we don't want to give more info than needed
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    nonce = os.urandom(32).hex()  # Generate a unique, random challenge (nonce)

    # Create a short-lived token containing the nonce and user/device info
    challenge_token = create_challenge_token(user_id=user.id, device_id=device.id, nonce=nonce)

    return ChallengeResponse(
        master_password_salt=user.master_password_salt,
        challenge_token=challenge_token,
    )


@router.post("/token", response_model=TokenResponse)
def login_with_challenge(request: TokenRequest, session: Annotated[Session, Depends(get_session)]):
    """
    Step 2 of login.
    Client provides the challenge token and a signature of the nonce.
    Server verifies the signature and issues a long-lived session JWT.
    """
    try:
        # Decode the challenge token to get the original nonce and IDs
        payload = jwt.decode(request.challenge_token, get_settings().challenge_secret_key, algorithms=get_settings().algorithm)
        user_id = uuid.UUID(payload.get("user_id"))
        device_id = uuid.UUID(payload.get("device_id"))
        nonce = payload.get("nonce")
    except (jwt.PyJWTError, TypeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    device = session.get(Device, device_id)
    if not device or device.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    # Verify the signature
    # This proves the client has the device's private key
    is_valid_signature = verify_signature(
        public_key_bytes=device.public_key,
        signature=request.signature,
        data=nonce.encode(),
    )

    if not is_valid_signature:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    # If signature is valid, authentication is successful.
    # Create the final, long-lived access token for the session.
    access_token = create_access_token(user_id=user_id, device_id=device_id)

    return TokenResponse(access_token=access_token)
