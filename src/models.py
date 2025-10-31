import uuid
from datetime import datetime
from typing import Literal, Union

from pydantic import AwareDatetime, EmailStr, computed_field
from sqlmodel import Column, Field, ForeignKey, LargeBinary, Relationship, SQLModel

from src import model_types
from src.enums import ShareStatus, VaultRole
from src.utils import datetime_utcnow

from .model_types import B64Bytes


class UserBase(SQLModel):
    email: EmailStr
    master_password_hash: str
    master_password_salt: str
    public_key: B64Bytes = Field(sa_column=Column(LargeBinary, nullable=False))
    encrypted_private_key: B64Bytes = Field(sa_column=Column(LargeBinary, nullable=False))


class DeviceBase(SQLModel):
    device_name: str
    public_key: B64Bytes = Field(sa_column=Column(LargeBinary, nullable=False))
    encrypted_private_key_blob: B64Bytes = Field(sa_column=Column(LargeBinary, nullable=False))
    encrypted_wrapping_key: B64Bytes = Field(sa_column=Column(LargeBinary, nullable=False))


class VaultItemBase(SQLModel):
    blob: B64Bytes = Field(sa_column=Column(LargeBinary, nullable=False))
    item_key: B64Bytes = Field(sa_column=Column(LargeBinary, nullable=False))


class VaultBase(SQLModel):
    name: str | None = None


# --- DB Tables ---
class VaultShare(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True, index=True)
    role: VaultRole = Field(default=VaultRole.VIEWER)
    status: ShareStatus = Field(default=ShareStatus.PENDING)

    vault_id: uuid.UUID = Field(foreign_key="vault.id")
    vault: "Vault" = Relationship(back_populates="shares")

    user_id: uuid.UUID = Field(foreign_key="user.id")
    user: "User" = Relationship(back_populates="shares")

    # metadata
    created_at: datetime = Field(default_factory=datetime_utcnow)
    updated_at: datetime = Field(
        default_factory=datetime_utcnow, sa_column_kwargs={"onupdate": datetime_utcnow}
    )


class Vault(VaultBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True, index=True)

    # Owner of the vault
    owner_id: uuid.UUID = Field(foreign_key="user.id")
    owner: "User" = Relationship(
        back_populates="owned_vaults", sa_relationship_kwargs={"foreign_keys": "Vault.owner_id"}
    )

    # Which user is this vault the default for
    default_for_user: Union["User", None] = Relationship(
        back_populates="default_vault",
        sa_relationship_kwargs={"foreign_keys": "User.default_vault_id"},
    )
    vault_items: list["VaultItem"] = Relationship(back_populates="vault")
    shares: list["VaultShare"] = Relationship(back_populates="vault")

    # metadata
    created_at: datetime = Field(default_factory=datetime_utcnow)


class User(UserBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True, index=True)

    default_vault_id: uuid.UUID | None = Field(
        default=None,
        sa_column=Column(ForeignKey("vault.id", use_alter=True), unique=True),
    )
    default_vault: Vault | None = Relationship(
        back_populates="default_for_user",
        sa_relationship_kwargs={"foreign_keys": "User.default_vault_id"},
    )

    owned_vaults: list[Vault] = Relationship(
        back_populates="owner", sa_relationship_kwargs={"foreign_keys": "Vault.owner_id"}
    )
    shares: list[VaultShare] = Relationship(back_populates="user")
    devices: list["Device"] = Relationship(back_populates="user")
    public_links: list["PublicLink"] = Relationship(back_populates="user")

    # metadata
    registered_at: datetime = Field(default_factory=datetime_utcnow)


class Device(DeviceBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True, index=True)
    signature: B64Bytes | None = Field(default=None, sa_column=Column(LargeBinary))

    user_id: uuid.UUID = Field(foreign_key="user.id")
    user: User = Relationship(back_populates="devices")

    # metadata
    registered_at: datetime = Field(default_factory=datetime_utcnow)


class VaultItem(VaultItemBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True, index=True)

    vault_id: uuid.UUID = Field(foreign_key="vault.id", nullable=False)
    vault: Vault = Relationship(back_populates="vault_items")

    public_links: list["PublicLink"] = Relationship(back_populates="vault_item")

    # metadata
    created_at: datetime = Field(default_factory=datetime_utcnow)
    updated_at: datetime = Field(
        default_factory=datetime_utcnow, sa_column_kwargs={"onupdate": datetime_utcnow}
    )


class PublicLink(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True, index=True)

    encrypted_blob: B64Bytes = Field(sa_column=Column(LargeBinary, nullable=False))

    expires_at: AwareDatetime = Field(sa_column=Column(model_types.AwareDateTime))
    max_views: int | None = Field(default=None)
    current_views: int = Field(default=0, nullable=False)

    user_id: uuid.UUID = Field(foreign_key="user.id")
    user: User = Relationship(back_populates="public_links")

    vault_item_id: uuid.UUID = Field(foreign_key="vaultitem.id")
    vault_item: VaultItem = Relationship(back_populates="public_links")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def expiration_timestamp(self) -> float:
        return self.expires_at.timestamp()


# --- API Models ---


class DeviceCreate(DeviceBase):
    pass


class DeviceApprove(SQLModel):
    device_id_to_approve: uuid.UUID
    signature: B64Bytes


# --- API Data Models for Authentication ---
class UserCreate(UserBase):
    device_name: str
    device_public_key: B64Bytes
    device_encrypted_private_key_blob: B64Bytes
    device_encrypted_wrapping_key: B64Bytes


class UserCreateResponse(SQLModel):
    user_id: uuid.UUID
    device_id: uuid.UUID
    status: Literal["success", "failure"]


class ChallengeRequest(SQLModel):
    """Client sends this to start the login process."""

    email: EmailStr
    device_id: uuid.UUID


class ChallengeResponse(SQLModel):
    """Server responds with the salt and a temporary challenge token."""

    master_password_salt: str
    challenge_token: str


class TokenRequest(SQLModel):
    """Client sends this back after solving the challenge."""

    challenge_token: str
    signature: B64Bytes  # The signature proves the client has the device's private key.


class TokenResponse(SQLModel):
    """Server responds with the final session token upon success."""

    access_token: str
    token_type: str = "bearer"


# --- API Data Models for Vaults ---
class VaultCreate(SQLModel):
    name: str
    description: str | None = None


class VaultRead(VaultCreate):
    id: uuid.UUID
    owner_id: uuid.UUID


class VaultUpdate(SQLModel):
    name: str | None = None
    description: str | None = None


# --- API Data Models for Vault items ---
class VaultItemCreate(VaultItemBase):
    vault_id: uuid.UUID


class VaultItemReadPublicLink(SQLModel):
    id: uuid.UUID
    expires_at: AwareDatetime = Field(exclude=True)
    current_views: int
    max_views: int | None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def expiration_timestamp(self) -> float:
        return self.expires_at.timestamp()


class VaultItemRead(VaultItemBase):
    id: uuid.UUID
    vault_id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    public_links: list[VaultItemReadPublicLink] = []


class VaultItemUpdate(SQLModel):
    blob: B64Bytes | None
    item_key: B64Bytes | None


class VaultItemMove(SQLModel):
    destination_vault_id: uuid.UUID


# --- API Data Models for Public Link Sharing ---
class PublicLinkCreateRequest(SQLModel):
    """Client sends this to create a new shareable link."""

    vault_item_id: uuid.UUID
    encrypted_blob: B64Bytes
    expires_in_hours: int = 24  # e.g., 1, 24, 168 (7 days)
    max_views: int | None = None


class PublicLinkCreateResponse(SQLModel):
    """Server responds with the unique ID for the link."""

    link_id: uuid.UUID
    expiration_timestamp: float


class PublicLinkReadResponse(SQLModel):
    """Server responds with the encrypted content for a public viewer."""

    contents: B64Bytes
    expiration_timestamp: float


# --- API Data Models for Vault Sharing ---
class VaultShareCreate(SQLModel):
    recipient_email: EmailStr
    role: VaultRole = VaultRole.VIEWER


class VaultShareResponse(SQLModel):
    user_id: uuid.UUID
    email: EmailStr
    role: VaultRole
    status: ShareStatus


class VaultShareUpdate(SQLModel):
    status: Literal[ShareStatus.ACCEPTED, ShareStatus.DECLINED]
