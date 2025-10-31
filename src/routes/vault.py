import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import selectinload
from sqlmodel import Session, select

from src.db import get_session
from src.models import User, VaultItem, VaultItemCreate, VaultItemRead
from src.security import get_current_user

router = APIRouter(prefix="/vault", tags=["Vault"])


@router.post("/", response_model=VaultItem, status_code=status.HTTP_201_CREATED)
def create_vault_item(
    item: VaultItemCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    "Create a new encrypted vault item for the authenticated user."
    # The client sends pre-encrypted data. The server just stores it.
    db_item = VaultItem.model_validate(
        item, update={"user_id": current_user.id}, from_attributes=True
    )

    session.add(db_item)
    session.commit()
    session.refresh(db_item)
    return db_item


@router.get("/", response_model=list[VaultItemRead])
def get_vault_items(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    "Retrieve all encrypted vault items for the authenticated user."
    query = (
        select(VaultItem)
        .where(VaultItem.user_id == current_user.id)
        .options(selectinload(VaultItem.public_links))
    )  # type: ignore[arg-type]
    items = session.exec(query).all()
    return items


@router.get("/{item_id}", response_model=VaultItemRead)
def get_vault_item_by_id(
    item_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    "Get a single vault item by its ID, with its public links nested inside."
    query = (
        select(VaultItem)
        .where(VaultItem.user_id == current_user.id, VaultItem.id == item_id)
        .options(selectinload(VaultItem.public_links))
    )  # type: ignore[arg-type]
    item = session.exec(query).first()

    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vault item not found")

    return item
