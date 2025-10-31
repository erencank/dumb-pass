import uuid
from typing import Annotated, Callable

from fastapi import Depends, HTTPException, status
from sqlmodel import Session

from src.db import get_session
from src.enums import VaultPermission
from src.models import User, Vault
from src.security import get_current_user


def require_vault_permission(
    required_permission: VaultPermission,
) -> Callable[[uuid.UUID, User, Session], Vault]:
    """
    Use this as Annotated[Vault, Depends(require_permission(VaultPermission.READ_PERMISSIONS))]
    """

    def get_vault_and_check_permission(
        vault_id: uuid.UUID,
        current_user: Annotated[User, Depends(get_current_user)],
        session: Annotated[Session, Depends(get_session)],
    ) -> Vault:
        """
        This is the actual dependency that will be executed by FastAPI.
        """
        vault = session.get(Vault, vault_id)
        if not vault:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vault not found")

        # Case 1: The user is the direct owner of the vault. Owners have all permissions.
        if vault.user_id == current_user.id:
            return vault

        return vault

    return get_vault_and_check_permission
