"""
Application configuration module.

This module centralizes all application configuration values including
security settings, JWT configuration, file upload paths, and environment settings.
"""
import json
import os
from pathlib import Path
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


def resolve_sqlite_path(db_url: str) -> Path:
    """Extract and resolve filesystem path from an SQLite database URL or path string.

    Supports formats:
    - sqlite:///./chat.db
    - sqlite:///chat.db
    - sqlite:////absolute/path/to/chat.db
    - sqlite:///C:/path/to/chat.db
    - relative or absolute path strings directly (e.g. "./chat.db")

    Raises:
        ValueError: If db_url is empty, in-memory, or not a supported SQLite URL.
    """
    if not db_url or not db_url.strip():
        raise ValueError("Database URL or path cannot be empty.")

    url = db_url.strip()
    if url in (":memory:", "sqlite:///:memory:", "sqlite:///:memory:?cache=shared"):
        raise ValueError("Cannot resolve filesystem path for an in-memory SQLite database.")

    if url.startswith("sqlite:///"):
        raw_path = url[len("sqlite:///"):]
    elif url.startswith("sqlite://"):
        raw_path = url[len("sqlite://"):]
    elif "://" in url:
        raise ValueError(f"Unsupported database scheme in URL: {url!r}. Only SQLite is supported.")
    else:
        raw_path = url

    return Path(raw_path).resolve()


VALID_ENVIRONMENTS: Set[str] = {"development", "production", "test"}
VALID_LOG_LEVELS: Set[str] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
MIN_PRODUCTION_SECRET_LEN: int = 32


class Settings:
    """Application settings container."""

    def __init__(
        self,
        _env_file: Optional[str] = None,
        ENVIRONMENT: Optional[str] = None,
        SECRET_KEY: Optional[str] = None,
        ALGORITHM: Optional[str] = None,
        ACCESS_TOKEN_EXPIRE_MINUTES: Optional[Union[int, str]] = None,
        DATABASE_URL: Optional[str] = None,
        UPLOADS_DIR: Optional[str] = None,
        STATIC_DIR: Optional[str] = None,
        ALLOWED_ORIGINS: Optional[Union[str, List[str]]] = None,
        BACKUP_DIR: Optional[str] = None,
        BACKUP_RETENTION_COUNT: Optional[Union[int, str]] = None,
        LOG_LEVEL: Optional[str] = None,
    ):
        if _env_file is not None:
            if os.path.exists(_env_file):
                load_dotenv(dotenv_path=_env_file, override=False)
        else:
            load_dotenv(override=False)

        # Environment mode (development / production / test)
        env_val = ENVIRONMENT or os.getenv("ENVIRONMENT") or os.getenv("APP_ENV") or "development"
        self.ENVIRONMENT: str = env_val.strip().lower()
        if self.ENVIRONMENT not in VALID_ENVIRONMENTS:
            raise ValueError(
                f"Invalid ENVIRONMENT: {self.ENVIRONMENT!r}. Must be one of: {', '.join(sorted(VALID_ENVIRONMENTS))}."
            )

        # JWT / Security configuration
        raw_secret = SECRET_KEY if SECRET_KEY is not None else os.getenv("SECRET_KEY")
        if self.is_production:
            if not raw_secret or not raw_secret.strip():
                raise RuntimeError("Production mode requires SECRET_KEY environment variable to be set.")
            if raw_secret.strip() in INSECURE_SECRETS:
                raise RuntimeError("Insecure placeholder SECRET_KEY is not permitted in production mode.")
            if len(raw_secret.strip()) < MIN_PRODUCTION_SECRET_LEN:
                raise RuntimeError(
                    f"Production mode requires a strong SECRET_KEY (minimum {MIN_PRODUCTION_SECRET_LEN} characters)."
                )
            self.SECRET_KEY: str = raw_secret.strip()
        else:
            # In development, fall back to safe development default if unset
            self.SECRET_KEY: str = raw_secret.strip() if (raw_secret and raw_secret.strip()) else DEV_DEFAULT_SECRET

        algo_val = ALGORITHM if ALGORITHM is not None else os.getenv("ALGORITHM", "HS256")
        if not algo_val or not algo_val.strip() or algo_val.strip().lower() == "none":
            raise RuntimeError("Insecure or empty JWT ALGORITHM is not permitted.")
        self.ALGORITHM: str = algo_val.strip()

        expire_val = (
            ACCESS_TOKEN_EXPIRE_MINUTES
            if ACCESS_TOKEN_EXPIRE_MINUTES is not None
            else os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")
        )
        try:
            self.ACCESS_TOKEN_EXPIRE_MINUTES: int = int(expire_val)
            if self.ACCESS_TOKEN_EXPIRE_MINUTES <= 0:
                raise ValueError()
        except (ValueError, TypeError):
            raise ValueError(f"ACCESS_TOKEN_EXPIRE_MINUTES must be a positive integer, got: {expire_val!r}")

        # Database configuration
        db_val = DATABASE_URL if DATABASE_URL is not None else os.getenv("DATABASE_URL", "sqlite:///./chat.db")
        if not db_val or not db_val.strip():
            raise RuntimeError("DATABASE_URL must be set and cannot be empty.")
        if "://" in db_val and not db_val.startswith("sqlite://"):
            raise RuntimeError(f"Unsupported database scheme in URL: {db_val!r}. Only SQLite is supported.")
        self.DATABASE_URL: str = db_val.strip()
        if self.is_production:
            is_explicit_in_memory = DATABASE_URL is not None and (
                self.DATABASE_URL in (":memory:", "sqlite:///:memory:", "sqlite:///:memory:?cache=shared")
                or ":memory:" in self.DATABASE_URL
            )
            is_env_prod_in_memory = os.getenv("ENVIRONMENT") == "production" and (
                self.DATABASE_URL in (":memory:", "sqlite:///:memory:", "sqlite:///:memory:?cache=shared")
                or ":memory:" in self.DATABASE_URL
            )
            if is_explicit_in_memory or is_env_prod_in_memory:
                raise RuntimeError("In-memory SQLite database is not permitted in production mode.")

        # File paths configuration
        self.UPLOADS_DIR: str = UPLOADS_DIR if UPLOADS_DIR is not None else os.getenv("UPLOADS_DIR", "uploads")
        self.STATIC_DIR: str = STATIC_DIR if STATIC_DIR is not None else os.getenv("STATIC_DIR", "static")

        # CORS Allowed Origins (configuration only)
        origins_val = ALLOWED_ORIGINS if ALLOWED_ORIGINS is not None else os.getenv("ALLOWED_ORIGINS")
        self.ALLOWED_ORIGINS: List[str] = parse_allowed_origins(origins_val, env=self.ENVIRONMENT)
        if self.is_production and "*" in self.ALLOWED_ORIGINS:
            raise RuntimeError(
                "Wildcard CORS origin ('*') is not permitted in production mode. "
                "Configure explicit origins via ALLOWED_ORIGINS."
            )

        # Logging level configuration (S5-T07 / S5-T09)
        raw_level = LOG_LEVEL if LOG_LEVEL is not None else os.getenv("LOG_LEVEL", "INFO")
        self.LOG_LEVEL: str = raw_level.strip().upper()
        if self.LOG_LEVEL not in VALID_LOG_LEVELS:
            raise ValueError(
                f"Invalid LOG_LEVEL: {self.LOG_LEVEL!r}. Must be one of: {', '.join(sorted(VALID_LOG_LEVELS))}."
            )

        # Backup & Recovery configuration (S5-T08)
        self.BACKUP_DIR: str = BACKUP_DIR if BACKUP_DIR is not None else os.getenv("BACKUP_DIR", "backups")
        retention_val = (
            BACKUP_RETENTION_COUNT
            if BACKUP_RETENTION_COUNT is not None
            else os.getenv("BACKUP_RETENTION_COUNT", "7")
        )
        try:
            self.BACKUP_RETENTION_COUNT: int = max(1, int(retention_val))
        except (ValueError, TypeError):
            self.BACKUP_RETENTION_COUNT = 7

    @property
    def is_production(self) -> bool:
        """Return True if running in production mode."""
        return self.ENVIRONMENT == "production"

    def get_sqlite_db_path(self) -> Path:
        """Resolve the SQLite database filesystem path from DATABASE_URL.

        Raises:
            ValueError: If DATABASE_URL is not a file-based SQLite database.
        """
        return resolve_sqlite_path(self.DATABASE_URL)

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
            f"ALLOWED_ORIGINS={self.ALLOWED_ORIGINS!r}, "
            f"LOG_LEVEL={self.LOG_LEVEL!r}, "
            f"BACKUP_DIR={self.BACKUP_DIR!r}, "
            f"BACKUP_RETENTION_COUNT={self.BACKUP_RETENTION_COUNT!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


# Create a singleton instance for easy importing
settings = Settings()
