import uuid

from pydantic import EmailStr
from sqlmodel import Column, Field, LargeBinary, Relationship, SQLModel


class UserBase(SQLModel):
    email: EmailStr
    master_password_hash: str
    master_password_salt: str
    public_key: bytes = Field(sa_column=Column(LargeBinary, nullable=False))
    encrypted_private_key: bytes = Field(sa_column=Column(LargeBinary, nullable=False))


class DeviceBase(SQLModel):
    device_name: str
    public_key: bytes = Field(sa_column=Column(LargeBinary, nullable=False))
    encrypted_private_key: bytes = Field(sa_column=Column(LargeBinary, nullable=False))


class VaultItemBase(SQLModel):
    blob: bytes = Field(sa_column=Column(LargeBinary, nullable=False))
    item_key: bytes = Field(sa_column=Column(LargeBinary, nullable=False))


class User(UserBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True, index=True)

    devices: list["Device"] = Relationship(back_populates="user")
    vault_items: list["VaultItem"] = Relationship(back_populates="user")


class Device(DeviceBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True, index=True)
    signature: bytes | None = Field(default=None, sa_column=Column(LargeBinary))

    user_id: uuid.UUID = Field(foreign_key="user.id")
    user: User = Relationship(back_populates="devices")


class VaultItem(VaultItemBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True, index=True)

    user_id: uuid.UUID = Field(foreign_key="user.id")
    user: User = Relationship(back_populates="vault_items")


class UserCreate(UserBase):
    device_name: str
    device_public_key: bytes
    device_encrypted_private_key: bytes


class DeviceCreate(DeviceBase):
    pass


class DeviceApprove(SQLModel):
    device_id_to_approve: uuid.UUID
    signature: bytes


class VaultItemCreate(VaultItemBase):
    pass


class VaultItemRead(VaultItemBase):
    id: uuid.UUID


class VaultItemUpdate(SQLModel):
    blob: bytes | None
    item_key: bytes | None
