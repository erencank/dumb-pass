from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from src.db import get_session
from src.models import Device, User, UserCreate

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get("/test")
def test(session: Annotated[Session, Depends(get_session)]):
    return {"users": session.exec(select(User)).all()}


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(request: UserCreate, session: Annotated[Session, Depends(get_session)]):
    existing_user = session.exec(select(User).where(User.email == request.email)).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    user = User.model_validate(request)

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

    return {"status": "success", "user_id": user.id, "device_id": device.id}
