import uuid
from typing import Annotated, Callable

from fastapi import Depends, HTTPException, status
from sqlmodel import Session, select

from src.db import get_session
from src.enums import ShareStatus, VaultPermission
from src.models import User, Vault, VaultShare
from src.permissions import VAULT_ROLE_PERMISSIONS
from src.security import get_current_user


def require_vault_permission(
    required_permission: VaultPermission,
) -> Callable[[uuid.UUID, User, Session], Vault]:
    """
    Use this as Annotated[Vault, Depends(require_vault_permission(VaultPermission.READ_PERMISSIONS))]
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
        if vault.owner_id == current_user.id:
            return vault

        # Case 2: The user is not the owner. Check if they have access via a share.
        share = session.exec(
            select(VaultShare).where(
                VaultShare.vault_id == vault_id,
                VaultShare.user_id == current_user.id,
                VaultShare.status == ShareStatus.ACCEPTED,
            )
        ).first()

        if not share:
            # If they aren't the owner and have no accepted share, they have no access.
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
            )

        # Case 3: The user has a share. Check if their role grants the required permission.
        user_permissions = VAULT_ROLE_PERMISSIONS.get(share.role, set())
        if required_permission not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
            )

        return vault

    return get_vault_and_check_permission
