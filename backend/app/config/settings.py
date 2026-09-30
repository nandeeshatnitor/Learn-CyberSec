"""Application settings, loaded from environment variables (and an optional .env file).

No secrets have defaults here: DATABASE_URL must be provided by the environment.
"""

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        # Repo-root .env for host-based development; containers get real env vars instead.
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "CVE Learning Explorer API"
    environment: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_json: bool = False

    # Required: no default so a missing value fails loudly instead of using a guessable credential.
    database_url: SecretStr
    redis_url: SecretStr | None = None

    # Origins (comma-separated in the environment) allowed to call the API from a browser.
    cors_allowed_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # Upper bound applied to every paginated endpoint.
    max_page_size: int = Field(default=50, ge=1, le=200)

    @field_validator("redis_url", mode="before")
    @classmethod
    def _empty_redis_url_is_unset(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # values come from the environment
