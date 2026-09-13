"""
Application configuration module.

This module centralizes all application configuration values including
security settings, JWT configuration, file upload paths, and environment settings.
"""
import json
import os
from typing import List, Optional, Set, Union
from dotenv import load_dotenv

# Insecure placeholder secrets that must never be permitted in production
INSECURE_SECRETS: Set[str] = {
    "super-secret-key-change-later",
    "dev-secret-key-change-in-production",
    "changethis",
    "secret",
    "change-me",
    "your-secret-key",
}

DEV_DEFAULT_SECRET: str = "dev-secret-key-change-in-production"


def parse_allowed_origins(val: Union[str, List[str], None], env: str = "development") -> List[str]:
    """Parse ALLOWED_ORIGINS configuration value."""
    if val is None:
        return ["*"] if env != "production" else []
    if isinstance(val, list):
        return [str(origin).strip() for origin in val if str(origin).strip()]
    val = val.strip()
    if not val:
        return []
    if val.startswith("[") and val.endswith("]"):
        try:
            parsed = json.loads(val)
            if isinstance(parsed, list):
                return [str(origin).strip() for origin in parsed if str(origin).strip()]
        except json.JSONDecodeError:
            pass
    return [origin.strip() for origin in val.split(",") if origin.strip()]


class Settings:
    """Application settings container."""

    def __init__(
        self,
        _env_file: Optional[str] = None,
        ENVIRONMENT: Optional[str] = None,
        SECRET_KEY: Optional[str] = None,
        ALGORITHM: Optional[str] = None,
        ACCESS_TOKEN_EXPIRE_MINUTES: Optional[int] = None,
        DATABASE_URL: Optional[str] = None,
        UPLOADS_DIR: Optional[str] = None,
        STATIC_DIR: Optional[str] = None,
        ALLOWED_ORIGINS: Optional[Union[str, List[str]]] = None,
    ):
        if _env_file is not None:
            if os.path.exists(_env_file):
                load_dotenv(dotenv_path=_env_file, override=False)
        else:
            load_dotenv(override=False)

        # Environment mode (development / production / test)
        env_val = ENVIRONMENT or os.getenv("ENVIRONMENT") or os.getenv("APP_ENV") or "development"
        self.ENVIRONMENT: str = env_val.strip().lower()

        # JWT / Security configuration
        raw_secret = SECRET_KEY if SECRET_KEY is not None else os.getenv("SECRET_KEY")
        if self.is_production:
            if not raw_secret or not raw_secret.strip():
                raise RuntimeError("Production mode requires SECRET_KEY environment variable to be set.")
            if raw_secret.strip() in INSECURE_SECRETS:
                raise RuntimeError("Insecure placeholder SECRET_KEY is not permitted in production mode.")
            self.SECRET_KEY: str = raw_secret.strip()
        else:
            # In development, fall back to safe development default if unset
            self.SECRET_KEY: str = raw_secret.strip() if (raw_secret and raw_secret.strip()) else DEV_DEFAULT_SECRET

        self.ALGORITHM: str = ALGORITHM or os.getenv("ALGORITHM", "HS256")

        expire_val = (
            ACCESS_TOKEN_EXPIRE_MINUTES
            if ACCESS_TOKEN_EXPIRE_MINUTES is not None
            else os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")
        )
        self.ACCESS_TOKEN_EXPIRE_MINUTES: int = int(expire_val)

        # Database configuration
        self.DATABASE_URL: str = DATABASE_URL or os.getenv("DATABASE_URL", "sqlite:///./chat.db")

        # File paths configuration
        self.UPLOADS_DIR: str = UPLOADS_DIR or os.getenv("UPLOADS_DIR", "uploads")
        self.STATIC_DIR: str = STATIC_DIR or os.getenv("STATIC_DIR", "static")

        # CORS Allowed Origins (configuration only)
        origins_val = ALLOWED_ORIGINS if ALLOWED_ORIGINS is not None else os.getenv("ALLOWED_ORIGINS")
        self.ALLOWED_ORIGINS: List[str] = parse_allowed_origins(origins_val, env=self.ENVIRONMENT)

    @property
    def is_production(self) -> bool:
        """Return True if running in production mode."""
        return self.ENVIRONMENT == "production"

    def __repr__(self) -> str:
        return (
            f"Settings("
            f"ENVIRONMENT={self.ENVIRONMENT!r}, "
            f"SECRET_KEY='***', "
            f"ALGORITHM={self.ALGORITHM!r}, "
            f"ACCESS_TOKEN_EXPIRE_MINUTES={self.ACCESS_TOKEN_EXPIRE_MINUTES!r}, "
            f"DATABASE_URL={self.DATABASE_URL!r}, "
            f"UPLOADS_DIR={self.UPLOADS_DIR!r}, "
            f"STATIC_DIR={self.STATIC_DIR!r}, "
            f"ALLOWED_ORIGINS={self.ALLOWED_ORIGINS!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


# Create a singleton instance for easy importing
settings = Settings()
