import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI

from src.core.logging import setup_logger
from src.db import init_db

from .core.config import get_settings

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
    return app


app = get_app()


@app.get("/")
def read_root():
    return {"status": "API is running"}
