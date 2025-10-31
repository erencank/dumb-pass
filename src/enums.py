from enum import StrEnum


class VaultPermission(StrEnum):
    READ_ITEMS = "read_items"  # At least viewer
    CREATE_ITEMS = "create_items"  # At least editor
    EDIT_ITEMS = "edit_items"  # At least editor
    DELETE_ITEMS = "delete_items"  # At least editor
    MOVE_ITEMS = "move_items"  # At least editor
    EDIT_NAME = "edit_name"  # At least admin
    MANAGE_SHARES = "manage_shares"  # At least admin
    DELETE_VAULT = "delete_vault"  # At least owner
    TRANSFER_OWNERSHIP = "transfer_ownership"  # At least owner


class VaultRole(StrEnum):
    VIEWER = "viewer"
    EDITOR = "editor"
    ADMIN = "admin"
    # "Owner" is not a role here. Ownership is a direct relationship.


class ShareStatus(StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    DECLINED = "declined"
