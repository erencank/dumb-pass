import uuid
from datetime import datetime
from typing import Literal

from pydantic import AwareDatetime, EmailStr, computed_field
from sqlmodel import Column, Field, LargeBinary, Relationship, SQLModel

from src import model_types
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


# --- DB Tables ---
class User(UserBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True, index=True)

    devices: list["Device"] = Relationship(back_populates="user")
    vault_items: list["VaultItem"] = Relationship(back_populates="user")
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

    user_id: uuid.UUID = Field(foreign_key="user.id")
    user: User = Relationship(back_populates="vault_items")

    public_links: list["PublicLink"] = Relationship(back_populates="vault_item")

    # metadata
    created_at: datetime = Field(default_factory=datetime_utcnow)
    updated_at: datetime = Field(default_factory=datetime_utcnow, sa_column_kwargs={"onupdate": datetime_utcnow})


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
class UserCreate(UserBase):
    device_name: str
    device_public_key: B64Bytes
    device_encrypted_private_key_blob: B64Bytes
    device_encrypted_wrapping_key: B64Bytes


class DeviceCreate(DeviceBase):
    pass


class DeviceApprove(SQLModel):
    device_id_to_approve: uuid.UUID
    signature: B64Bytes


class VaultItemCreate(VaultItemBase):
    pass


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
    created_at: datetime
    updated_at: datetime
    public_links: list[VaultItemReadPublicLink] = []


class VaultItemUpdate(SQLModel):
    blob: B64Bytes | None
    item_key: B64Bytes | None


# --- API Data Models for Authentication ---
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
