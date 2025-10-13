import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI

from src.core.logging import setup_logger
from src.db import init_db

from .core.config import get_settings
from .routes.auth import router as auth_router
from .routes.vault import router as vault_router

settings = get_settings()
setup_logger()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("Starting up...")
    init_db()
    yield
    logger.info("Shutting down...")
    logger.info("Finished shutting down.")


def get_app() -> FastAPI:
    app = FastAPI(title="Password Manager API", lifespan=lifespan)
    app.include_router(auth_router)
    app.include_router(vault_router)
    return app


app = get_app()
