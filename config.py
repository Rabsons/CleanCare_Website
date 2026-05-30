"""
core/config.py — Application Settings
======================================
All configuration is loaded exclusively from environment variables (or a .env
file in development).  No secrets ever appear in source code.

Pydantic-Settings validates every value at startup; the application will refuse
to start if a required variable is missing or has an invalid type/value.
"""

from __future__ import annotations

import secrets
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import AnyHttpUrl, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppEnvironment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class LogFormat(str, Enum):
    JSON = "json"
    TEXT = "text"


class Settings(BaseSettings):
    """
    Single source of truth for all application configuration.
    Values are loaded from environment variables; .env file is used in dev.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",           # Silently ignore unknown env vars
    )

    # -------------------------------------------------------------------------
    # Application
    # -------------------------------------------------------------------------
    APP_ENV: AppEnvironment = AppEnvironment.DEVELOPMENT
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = Field(default=8000, ge=1, le=65535)
    APP_BASE_URL: AnyHttpUrl = "https://cleancare.example.com"  # type: ignore[assignment]
    SECRET_KEY: str = Field(..., min_length=64)  # Enforces minimum 64-char secret
    DEBUG: bool = False

    # -------------------------------------------------------------------------
    # Database
    # -------------------------------------------------------------------------
    DATABASE_URL: str = "sqlite+aiosqlite:///./cleancare_dev.db"
    DB_POOL_SIZE: int = Field(default=10, ge=1, le=100)
    DB_MAX_OVERFLOW: int = Field(default=20, ge=0, le=100)
    DB_ECHO: bool = False

    # -------------------------------------------------------------------------
    # Redis
    # -------------------------------------------------------------------------
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: str = ""
    REDIS_SSL: bool = False

    # -------------------------------------------------------------------------
    # Session
    # -------------------------------------------------------------------------
    SESSION_ABSOLUTE_TIMEOUT_SECONDS: int = Field(default=28800, ge=300)   # 8 h
    SESSION_IDLE_TIMEOUT_SECONDS: int = Field(default=1800, ge=60)          # 30 min
    SESSION_MAX_CONCURRENT: int = Field(default=3, ge=1, le=10)
    SESSION_COOKIE_NAME: str = "session"
    SESSION_STRICT_IP_BINDING: bool = False

    # -------------------------------------------------------------------------
    # CSRF
    # -------------------------------------------------------------------------
    CSRF_COOKIE_NAME: str = "csrf_token"
    CSRF_HEADER_NAME: str = "X-CSRF-Token"
    CSRF_TOKEN_ROTATION_DAYS: int = Field(default=1, ge=1, le=7)

    # -------------------------------------------------------------------------
    # Rate Limiting
    # -------------------------------------------------------------------------
    RATE_LIMIT_LOGIN_ATTEMPTS: int = Field(default=5, ge=1)
    RATE_LIMIT_LOGIN_WINDOW_SECONDS: int = Field(default=900, ge=60)
    RATE_LIMIT_REGISTER_ATTEMPTS: int = Field(default=3, ge=1)
    RATE_LIMIT_REGISTER_WINDOW_SECONDS: int = Field(default=3600, ge=60)
    RATE_LIMIT_PASSWORD_RESET_ATTEMPTS: int = Field(default=3, ge=1)
    RATE_LIMIT_PASSWORD_RESET_WINDOW_SECONDS: int = Field(default=3600, ge=60)
    RATE_LIMIT_UPLOAD_ATTEMPTS: int = Field(default=10, ge=1)
    RATE_LIMIT_UPLOAD_WINDOW_SECONDS: int = Field(default=3600, ge=60)

    # -------------------------------------------------------------------------
    # Account Lockout
    # -------------------------------------------------------------------------
    LOCKOUT_FAILURE_THRESHOLD: int = Field(default=10, ge=3)
    LOCKOUT_CAPTCHA_THRESHOLD: int = Field(default=5, ge=1)
    LOCKOUT_DURATION_SECONDS: int = Field(default=900, ge=60)
    LOCKOUT_ALERT_THRESHOLD: int = Field(default=20, ge=10)

    # -------------------------------------------------------------------------
    # Password Policy
    # -------------------------------------------------------------------------
    PASSWORD_MIN_LENGTH: int = Field(default=12, ge=12)
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGIT: bool = True
    PASSWORD_REQUIRE_SYMBOL: bool = True
    PASSWORD_HIBP_CHECK: bool = True

    # -------------------------------------------------------------------------
    # Email
    # -------------------------------------------------------------------------
    MAIL_SERVER: str = "smtp.example.com"
    MAIL_PORT: int = Field(default=587, ge=1, le=65535)
    MAIL_USERNAME: str = "noreply@cleancare.example.com"
    MAIL_PASSWORD: str = ""
    MAIL_USE_TLS: bool = True
    MAIL_FROM: str = "noreply@cleancare.example.com"
    MAIL_FROM_NAME: str = "CleanCare Solutions"
    EMAIL_VERIFY_TOKEN_EXPIRE_HOURS: int = Field(default=24, ge=1, le=72)
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = Field(default=15, ge=5, le=60)

    # -------------------------------------------------------------------------
    # File Uploads
    # -------------------------------------------------------------------------
    UPLOAD_MAX_SIZE_BYTES: int = Field(default=5_242_880, ge=1024)  # 5 MB
    UPLOAD_STORAGE_PATH: Path = Path("/private/uploads")
    UPLOAD_SIGNED_URL_EXPIRE_MINUTES: int = Field(default=60, ge=5, le=1440)
    UPLOAD_ALLOWED_MIME_TYPES: str = "image/jpeg,image/png,image/webp,application/pdf"

    # -------------------------------------------------------------------------
    # CORS
    # -------------------------------------------------------------------------
    CORS_ALLOWED_ORIGINS: str = "https://cleancare.example.com"

    # -------------------------------------------------------------------------
    # MFA
    # -------------------------------------------------------------------------
    MFA_ISSUER_NAME: str = "CleanCare Solutions"
    MFA_TOTP_WINDOW: int = Field(default=1, ge=0, le=2)

    # -------------------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------------------
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: LogFormat = LogFormat.JSON
    LOG_SECURITY_EVENTS: bool = True

    # -------------------------------------------------------------------------
    # Derived / computed helpers
    # -------------------------------------------------------------------------

    @field_validator("SECRET_KEY")
    @classmethod
    def secret_key_must_not_be_default(cls, v: str) -> str:
        forbidden = {"CHANGE_ME_use_openssl_rand_hex_64", "changeme", "secret", ""}
        if v.lower() in {f.lower() for f in forbidden}:
            raise ValueError(
                "SECRET_KEY is set to a placeholder value. "
                "Generate a real key with: openssl rand -hex 64"
            )
        return v

    @model_validator(mode="after")
    def production_must_not_debug(self) -> "Settings":
        if self.APP_ENV == AppEnvironment.PRODUCTION and self.DEBUG:
            raise ValueError("DEBUG must be false in production.")
        if self.APP_ENV == AppEnvironment.PRODUCTION and self.DB_ECHO:
            raise ValueError("DB_ECHO must be false in production.")
        return self

    # Parsed helpers — avoids re-splitting on every access
    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ALLOWED_ORIGINS.split(",") if o.strip()]

    @property
    def upload_allowed_mime_list(self) -> List[str]:
        return [m.strip() for m in self.UPLOAD_ALLOWED_MIME_TYPES.split(",") if m.strip()]

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == AppEnvironment.PRODUCTION

    @property
    def is_development(self) -> bool:
        return self.APP_ENV == AppEnvironment.DEVELOPMENT


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Returns a cached Settings instance.
    Using lru_cache ensures the .env file is read exactly once at startup.
    Inject via FastAPI Depends(get_settings) in route handlers.
    """
    return Settings()


# Module-level singleton — used directly in non-DI contexts (middleware, etc.)
settings: Settings = get_settings()
