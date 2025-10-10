from typing import Generator

from sqlmodel import Session, SQLModel, create_engine

from . import models  # NOQA: F401
from .core.config import get_settings

engine = create_engine(str(get_settings().database_url), echo=True)


def init_db() -> None:
    SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, Session, None]:
    with Session(engine) as session:
        yield session
