from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables and .env files."""

    env: str = "dev"
    region: str = "us-east-1"
    arena_account_id: Optional[str] = None
    auth0_domain: Optional[str] = None
    auth0_audience: Optional[str] = None
    auth0_issuer: Optional[str] = None
    auth0_jwks_uri: Optional[str] = None
    auth0_client_id: Optional[str] = None
    auth0_client_secret: Optional[str] = None
    auth0_callback_url: Optional[str] = Field(default=None, env="AUTH0_CALLBACK_URL")
    auth0_logout_redirect_url: Optional[str] = Field(default=None, env="AUTH0_LOGOUT_REDIRECT_URL")
    gemini_api_key: Optional[str] = None
    aws_profile: str = "arena"
    use_gradient: bool = False
    database_url: str = Field(default="sqlite:///./cloudarena.db", env="DATABASE_URL")
    redis_url: str = "redis://redis:6379/0"
    celery_result_backend: Optional[str] = None
    auth_token: Optional[str] = None
    api_base_url: str = Field(default="http://api:8000", env="API_BASE_URL")
    session_secret: str = Field(default="change-me-session-secret", env="SESSION_SECRET")
    session_cookie_max_age: int = Field(default=60 * 60 * 8, env="SESSION_COOKIE_MAX_AGE")
    session_cookie_secure: bool = Field(default=False, env="SESSION_COOKIE_SECURE")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def data_dir(self) -> Optional[Path]:
        if self.database_url.startswith("sqlite:////data/"):
            return Path("/data")
        return None


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()
