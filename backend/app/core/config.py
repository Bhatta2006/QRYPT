# =============================================================================
# SVT System — Application Configuration
# =============================================================================
# Pydantic Settings: env-based configuration with validation
# =============================================================================

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=["../.env", ".env"],
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application ---
    app_env: Literal["development", "staging", "production"] = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    app_log_level: str = "INFO"
    app_cors_origins: str = "http://localhost:5173,http://localhost:3000"

    # --- Database ---
    database_url: str = "postgresql+asyncpg://svt_app:svt_dev_password@localhost:5432/svt"
    db_pool_size: int = 20
    db_max_overflow: int = 10
    db_pool_timeout: int = 30

    # --- Redis ---
    redis_url: str = "redis://:svt_dev_redis_password@localhost:6379/0"

    # --- JWT ---
    jwt_secret_key: str = "CHANGE_ME_in_production_64_chars_minimum"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 15
    jwt_refresh_token_expire_days: int = 7

    # --- KMS ---
    kms_key_name: str = "projects/svt-project/locations/global/keyRings/svt-keyring/cryptoKeys/svt-issuer-keys"
    kms_provider: Literal["local", "gcp"] = "local"

    # --- GeoIP ---
    geoip_db_path: str = "/app/data/GeoLite2-City.mmdb"

    # --- Webhooks ---
    admin_webhook_url: str = ""

    # --- Observability ---
    otel_exporter_otlp_endpoint: str = "http://localhost:4317"
    otel_service_name: str = "svt-backend"

    @field_validator("app_cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: str) -> str:
        return v

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.app_cors_origins.split(",")]

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"


@lru_cache
def get_settings() -> Settings:
    """Cached settings instance."""
    return Settings()
