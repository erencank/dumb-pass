import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session

from src.db import get_session
from src.dependencies import require_vault_permission
from src.enums import VaultPermission
from src.models import User, Vault, VaultItem, VaultItemCreate, VaultItemMove, VaultItemRead
from src.security import get_current_user

router = APIRouter(prefix="/items", tags=["Vault Items"])


@router.post("/", response_model=VaultItem, status_code=status.HTTP_201_CREATED)
def create_vault_item(
    item: VaultItemCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    "Create a new encrypted vault item for the authenticated user."
    # The client sends pre-encrypted data. The server just stores it.
    db_item = VaultItem.model_validate(item, from_attributes=True)

    session.add(db_item)
    session.commit()
    session.refresh(db_item)
    return db_item


@router.get("/by-vault/{vault_id}", response_model=list[VaultItemRead])
def get_vault_items(
    vault_id: uuid.UUID,
    vault: Annotated[Vault, Depends(require_vault_permission(VaultPermission.READ_ITEMS))],
    session: Annotated[Session, Depends(get_session)],
):
    "Retrieve all encrypted vault items for the authenticated user."
    return vault.vault_items


@router.put("/{item_id}/move", response_model=VaultItemRead)
def move_vault_item(
    item_id: uuid.UUID,
    move_request: VaultItemMove,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    db_item = session.get(VaultItem, item_id)
    # Verify user owns the item's current vault
    if not db_item or db_item.vault.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")

    # Verify user owns the destination vault
    destination_vault = session.get(Vault, move_request.destination_vault_id)
    if not destination_vault or destination_vault.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to move items to this vault",
        )

    db_item.vault_id = move_request.destination_vault_id
    session.add(db_item)
    session.commit()
    session.refresh(db_item)
    return db_item
