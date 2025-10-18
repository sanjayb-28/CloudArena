from functools import lru_cache
from typing import Optional

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
    database_url: str = "sqlite:///./cloudarena.db"
    redis_url: str = "redis://redis:6379/0"
    celery_result_backend: Optional[str] = None
    auth_token: Optional[str] = None
    api_base_url: str = "http://api:8000"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()
