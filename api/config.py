import os
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """12-factor application settings loaded from environment variables or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Dragon-GPT Cloud Native API"
    app_version: str = "0.1.0"
    env: str = "development"
    debug: bool = False

    # Server binding
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"

    # CORS configuration
    cors_origins: List[str] = ["*"]

    # AI / LLM Configuration
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o-mini"
    openai_base_url: Optional[str] = None
    default_temperature: float = 0.2

    # Observability
    enable_metrics: bool = True


# Global cached settings instance
settings = Settings()
