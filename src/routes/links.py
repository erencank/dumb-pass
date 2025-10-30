import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session

from src.db import get_session
from src.models import PublicLink, PublicLinkCreateRequest, PublicLinkCreateResponse, PublicLinkReadResponse, User
from src.security import get_current_user

router = APIRouter(prefix="/links", tags=["Public Links"])


@router.post("/", response_model=PublicLinkCreateResponse, status_code=status.HTTP_201_CREATED)
def create_public_link(
    request: PublicLinkCreateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    """
    Authenticated endpoint for a user to create a new secure link.
    The server receives the already-encrypted blob and stores it.
    """

    expiration = datetime.now(timezone.utc) + timedelta(hours=request.expires_in_hours)

    new_link = PublicLink.model_validate(request, update={"expires_at": expiration, "user_id": current_user.id}, from_attributes=True)

    session.add(new_link)
    session.commit()
    session.refresh(new_link)

    return PublicLinkCreateResponse(link_id=new_link.id, expiration_timestamp=expiration.timestamp())


@router.get("/{link_id}", response_model=PublicLinkReadResponse)
def get_public_link_content(link_id: uuid.UUID, session: Annotated[Session, Depends(get_session)]):
    """
    Public, unauthenticated endpoint for anyone with the link to retrieve the encrypted content.
    """
    link = session.get(PublicLink, link_id)

    # --- Security and Access Control Checks ---
    if not link:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Link not found")

    if link.expires_at and link.expires_at < datetime.now(timezone.utc):
        session.delete(link)
        session.commit()
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Link has expired or reached its view limit")

    if link.max_views is not None and link.current_views >= link.max_views:
        session.delete(link)
        session.commit()
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Link has expired or reached its view limit")

    # Increment the view count and save
    link.current_views += 1
    session.add(link)
    session.commit()
    session.refresh(link)

    return PublicLinkReadResponse(contents=link.encrypted_blob, expiration_timestamp=link.expires_at.timestamp())
