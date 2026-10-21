from functools import lru_cache

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, read from SHIELDPIPE_* environment variables.

    There is no default JWT secret on purpose: the service refuses to start without one.
    """

    model_config = SettingsConfigDict(env_prefix="SHIELDPIPE_", extra="ignore")

    jwt_secret: SecretStr
    jwt_issuer: str = "shieldpipe"
    jwt_audience: str = "shieldpipe-api"
    access_token_ttl_minutes: int = Field(default=15, ge=1, le=60)

    database_url: str = "sqlite:///./data/shieldpipe.db"

    login_max_attempts: int = Field(default=5, ge=1)
    login_window_seconds: int = Field(default=300, ge=1)
    max_body_bytes: int = Field(default=64 * 1024, ge=1024)
    expose_openapi: bool = False

    bootstrap_admin_username: str | None = None
    bootstrap_admin_password: SecretStr | None = None

    @field_validator("jwt_secret")
    @classmethod
    def _secret_is_long_enough(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < 32:
            raise ValueError("must be at least 32 characters")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
