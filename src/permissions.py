from .enums import VaultPermission, VaultRole

VAULT_ROLE_PERMISSIONS: dict[VaultRole, set[VaultPermission]] = {
    VaultRole.VIEWER: {
        VaultPermission.READ_ITEMS,
    },
    VaultRole.EDITOR: {
        VaultPermission.READ_ITEMS,
        VaultPermission.CREATE_ITEMS,
        VaultPermission.EDIT_ITEMS,
        VaultPermission.DELETE_ITEMS,
        VaultPermission.MOVE_ITEMS,
    },
    VaultRole.ADMIN: {
        VaultPermission.READ_ITEMS,
        VaultPermission.CREATE_ITEMS,
        VaultPermission.EDIT_ITEMS,
        VaultPermission.DELETE_ITEMS,
        VaultPermission.MOVE_ITEMS,
        VaultPermission.EDIT_NAME,
        VaultPermission.MANAGE_SHARES,
    },
}
