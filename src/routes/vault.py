from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlmodel import Session, select

from src.db import get_session
from src.models import User, VaultItem, VaultItemCreate
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
    db_item = VaultItem.model_validate(item, update={"user_id": current_user.id}, from_attributes=True)

    session.add(db_item)
    session.commit()
    session.refresh(db_item)
    return db_item


@router.get("/", response_model=list[VaultItem])
def get_vault_items(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    "Retrieve all encrypted vault items for the authenticated user."
    items = session.exec(select(VaultItem).where(VaultItem.user_id == current_user.id)).all()
    return items
