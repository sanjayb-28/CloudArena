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
    gemini_api_key: Optional[str] = None
    aws_profile: str = "arena"
    use_gradient: bool = False
    database_url: str = Field(default="sqlite:///./cloudarena.db", env="DATABASE_URL")
    redis_url: str = "redis://redis:6379/0"
    celery_result_backend: Optional[str] = None
    auth_token: Optional[str] = None
    api_base_url: str = Field(default="http://api:8000", env="API_BASE_URL")
    auth0_m2m_client_id: Optional[str] = None
    auth0_m2m_client_secret: Optional[str] = None
    auth0_m2m_audience: Optional[str] = None

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
