from pydantic import PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "dumb-pass"
    database_url: PostgresDsn
    postgres_db: str
    postgres_user: str
    postgres_password: str

    secret_key: str
    challenge_secret_key: str
    algorithm: str = "HS256"
    access_token_expiration_minutes: int = 15
    challenge_token_expiration_minutes: int = 2

    model_config = SettingsConfigDict(env_file=".env")


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()  # type: ignore[call-arg]
    return _settings
