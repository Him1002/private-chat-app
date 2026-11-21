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
        STUN_SERVER_URL: Optional[str] = None,
        TURN_SERVER_URL: Optional[str] = None,
        TURN_USERNAME: Optional[str] = None,
        TURN_CREDENTIAL: Optional[str] = None,
        CALL_TIMEOUT_SECONDS: Optional[Union[int, str]] = None,
        MAX_IMAGE_SIZE_BYTES: Optional[Union[int, str]] = None,
        MAX_VIDEO_SIZE_BYTES: Optional[Union[int, str]] = None,
        MAX_VIDEO_DURATION_SECONDS: Optional[Union[int, str]] = None,
        MAX_FILE_SIZE_BYTES: Optional[Union[int, str]] = None,
        MAX_VOICE_SIZE_BYTES: Optional[Union[int, str]] = None,
        MAX_VOICE_DURATION_SECONDS: Optional[Union[int, str]] = None,
        VAPID_PUBLIC_KEY: Optional[str] = None,
        VAPID_PRIVATE_KEY: Optional[str] = None,
        VAPID_CLAIMS_SUB: Optional[str] = None,
        WEB_PUSH_ENABLED: Optional[Union[bool, str]] = None,
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

        # WebRTC / Calling ICE configuration (V2 Calling Phase 1)
        raw_stun = STUN_SERVER_URL if STUN_SERVER_URL is not None else os.getenv("STUN_SERVER_URL", "stun:stun.l.google.com:19302")
        self.STUN_SERVER_URL: str = raw_stun.strip() if raw_stun else ""

        raw_turn = TURN_SERVER_URL if TURN_SERVER_URL is not None else os.getenv("TURN_SERVER_URL", "")
        self.TURN_SERVER_URL: str = raw_turn.strip() if raw_turn else ""

        raw_turn_user = TURN_USERNAME if TURN_USERNAME is not None else os.getenv("TURN_USERNAME", "")
        self.TURN_USERNAME: str = raw_turn_user.strip() if raw_turn_user else ""

        raw_turn_cred = TURN_CREDENTIAL if TURN_CREDENTIAL is not None else os.getenv("TURN_CREDENTIAL", "")
        self.TURN_CREDENTIAL: str = raw_turn_cred.strip() if raw_turn_cred else ""

        raw_timeout = CALL_TIMEOUT_SECONDS if CALL_TIMEOUT_SECONDS is not None else os.getenv("CALL_TIMEOUT_SECONDS", "30")
        try:
            self.CALL_TIMEOUT_SECONDS: int = max(5, int(raw_timeout))
        except (ValueError, TypeError):
            self.CALL_TIMEOUT_SECONDS = 30

        # Rich media upload limit (Phase R1: default 10 MB)
        raw_max_img = (
            MAX_IMAGE_SIZE_BYTES
            if MAX_IMAGE_SIZE_BYTES is not None
            else os.getenv("MAX_IMAGE_SIZE_BYTES", str(10 * 1024 * 1024))
        )
        try:
            self.MAX_IMAGE_SIZE_BYTES: int = max(1024, int(raw_max_img))
        except (ValueError, TypeError):
            self.MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024

        # Rich media video upload limit (Phase R2: default 50 MB)
        raw_max_video = (
            MAX_VIDEO_SIZE_BYTES
            if MAX_VIDEO_SIZE_BYTES is not None
            else os.getenv("MAX_VIDEO_SIZE_BYTES", str(50 * 1024 * 1024))
        )
        try:
            self.MAX_VIDEO_SIZE_BYTES: int = max(1024, int(raw_max_video))
        except (ValueError, TypeError):
            self.MAX_VIDEO_SIZE_BYTES = 50 * 1024 * 1024

        # Rich media video duration limit (Phase R2: default 120 seconds / 2 minutes)
        raw_max_duration = (
            MAX_VIDEO_DURATION_SECONDS
            if MAX_VIDEO_DURATION_SECONDS is not None
            else os.getenv("MAX_VIDEO_DURATION_SECONDS", "120")
        )
        try:
            self.MAX_VIDEO_DURATION_SECONDS: int = max(1, int(raw_max_duration))
        except (ValueError, TypeError):
            self.MAX_VIDEO_DURATION_SECONDS = 120

        # Rich media file upload limit (Phase R3: default 25 MB)
        raw_max_file = (
            MAX_FILE_SIZE_BYTES
            if MAX_FILE_SIZE_BYTES is not None
            else os.getenv("MAX_FILE_SIZE_BYTES", str(25 * 1024 * 1024))
        )
        try:
            self.MAX_FILE_SIZE_BYTES: int = max(1024, int(raw_max_file))
        except (ValueError, TypeError):
            self.MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024

        # Rich media voice message upload limit (Phase R4: default 10 MB)
        raw_max_voice = (
            MAX_VOICE_SIZE_BYTES
            if MAX_VOICE_SIZE_BYTES is not None
            else os.getenv("MAX_VOICE_SIZE_BYTES", str(10 * 1024 * 1024))
        )
        try:
            self.MAX_VOICE_SIZE_BYTES: int = max(1024, int(raw_max_voice))
        except (ValueError, TypeError):
            self.MAX_VOICE_SIZE_BYTES = 10 * 1024 * 1024

        # Rich media voice message duration limit (Phase R4: default 120 seconds / 2 minutes)
        raw_max_voice_duration = (
            MAX_VOICE_DURATION_SECONDS
            if MAX_VOICE_DURATION_SECONDS is not None
            else os.getenv("MAX_VOICE_DURATION_SECONDS", "120")
        )
        try:
            self.MAX_VOICE_DURATION_SECONDS: int = max(1, int(raw_max_voice_duration))
        except (ValueError, TypeError):
            self.MAX_VOICE_DURATION_SECONDS = 120

        # Web Push / VAPID configuration (V2 Task R7)
        raw_vapid_pub = VAPID_PUBLIC_KEY if VAPID_PUBLIC_KEY is not None else os.getenv("VAPID_PUBLIC_KEY")
        self.VAPID_PUBLIC_KEY: Optional[str] = raw_vapid_pub.strip() if raw_vapid_pub and raw_vapid_pub.strip() else None

        raw_vapid_priv = VAPID_PRIVATE_KEY if VAPID_PRIVATE_KEY is not None else os.getenv("VAPID_PRIVATE_KEY")
        self.VAPID_PRIVATE_KEY: Optional[str] = raw_vapid_priv.strip() if raw_vapid_priv and raw_vapid_priv.strip() else None

        raw_vapid_sub = VAPID_CLAIMS_SUB if VAPID_CLAIMS_SUB is not None else os.getenv("VAPID_CLAIMS_SUB")
        self.VAPID_CLAIMS_SUB: Optional[str] = raw_vapid_sub.strip() if raw_vapid_sub and raw_vapid_sub.strip() else None

        raw_push_enabled = WEB_PUSH_ENABLED if WEB_PUSH_ENABLED is not None else os.getenv("WEB_PUSH_ENABLED")
        if raw_push_enabled is not None:
            if isinstance(raw_push_enabled, bool):
                self.WEB_PUSH_ENABLED: bool = raw_push_enabled
            else:
                self.WEB_PUSH_ENABLED = str(raw_push_enabled).strip().lower() in ("true", "1", "yes", "on")
        else:
            # Development/test keeps Web Push disabled unless explicit valid VAPID configuration is supplied
            self.WEB_PUSH_ENABLED = bool(self.VAPID_PUBLIC_KEY and self.VAPID_PRIVATE_KEY and self.VAPID_CLAIMS_SUB)

        if self.is_production:
            if self.WEB_PUSH_ENABLED or self.VAPID_PUBLIC_KEY or self.VAPID_PRIVATE_KEY:
                if not self.VAPID_PRIVATE_KEY:
                    raise RuntimeError("Production mode requires VAPID_PRIVATE_KEY environment variable when Web Push is enabled.")
                if self.VAPID_PRIVATE_KEY in INSECURE_SECRETS:
                    raise RuntimeError("Insecure placeholder VAPID_PRIVATE_KEY is not permitted in production mode.")
                if not self.VAPID_PUBLIC_KEY:
                    raise RuntimeError("Production mode requires VAPID_PUBLIC_KEY environment variable when Web Push is enabled.")
                if not self.VAPID_CLAIMS_SUB:
                    raise RuntimeError("Production mode requires VAPID_CLAIMS_SUB environment variable when Web Push is enabled.")


    @property
    def is_production(self) -> bool:
        """Return True if running in production mode."""
        return self.ENVIRONMENT == "production"

    @property
    def is_web_push_configured(self) -> bool:
        """Return True if Web Push is enabled and all required VAPID settings are configured."""
        return bool(
            self.WEB_PUSH_ENABLED
            and self.VAPID_PUBLIC_KEY
            and self.VAPID_PRIVATE_KEY
            and self.VAPID_CLAIMS_SUB
        )

    def get_sqlite_db_path(self) -> Path:
        """Resolve the SQLite database filesystem path from DATABASE_URL.

        Raises:
            ValueError: If DATABASE_URL is not a file-based SQLite database.
        """
        return resolve_sqlite_path(self.DATABASE_URL)

    def get_stun_urls(self) -> List[str]:
        """Return parsed list of STUN server URLs."""
        if not self.STUN_SERVER_URL:
            return []
        return [u.strip() for u in self.STUN_SERVER_URL.split(",") if u.strip()]

    def get_turn_urls(self) -> List[str]:
        """Return parsed list of TURN server URLs."""
        if not self.TURN_SERVER_URL:
            return []
        return [u.strip() for u in self.TURN_SERVER_URL.split(",") if u.strip()]

    def get_ice_servers(self) -> List[dict]:
        """Return ICE server configuration list for WebRTC client initialization.

        Security note: In accordance with project security policies, TURN credentials
        must never be exposed in API responses or logs.
        """
        servers: List[dict] = []
        stun_urls = self.get_stun_urls()
        if stun_urls:
            servers.append({"urls": stun_urls})
        turn_urls = self.get_turn_urls()
        if turn_urls:
            entry: dict = {"urls": turn_urls}
            if self.TURN_USERNAME:
                entry["username"] = self.TURN_USERNAME
            servers.append(entry)
        return servers

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
            f"BACKUP_RETENTION_COUNT={self.BACKUP_RETENTION_COUNT!r}, "
            f"STUN_SERVER_URL={self.STUN_SERVER_URL!r}, "
            f"TURN_SERVER_URL={self.TURN_SERVER_URL!r}, "
            f"TURN_USERNAME={self.TURN_USERNAME!r}, "
            f"TURN_CREDENTIAL='***', "
            f"CALL_TIMEOUT_SECONDS={self.CALL_TIMEOUT_SECONDS!r}, "
            f"MAX_IMAGE_SIZE_BYTES={self.MAX_IMAGE_SIZE_BYTES!r}, "
            f"MAX_VIDEO_SIZE_BYTES={self.MAX_VIDEO_SIZE_BYTES!r}, "
            f"MAX_VIDEO_DURATION_SECONDS={self.MAX_VIDEO_DURATION_SECONDS!r}, "
            f"MAX_FILE_SIZE_BYTES={self.MAX_FILE_SIZE_BYTES!r}, "
            f"MAX_VOICE_SIZE_BYTES={self.MAX_VOICE_SIZE_BYTES!r}, "
            f"MAX_VOICE_DURATION_SECONDS={self.MAX_VOICE_DURATION_SECONDS!r}, "
            f"WEB_PUSH_ENABLED={self.WEB_PUSH_ENABLED!r}, "
            f"VAPID_PUBLIC_KEY={self.VAPID_PUBLIC_KEY!r}, "
            f"VAPID_PRIVATE_KEY={'***' if self.VAPID_PRIVATE_KEY else None!r}, "
            f"VAPID_CLAIMS_SUB={self.VAPID_CLAIMS_SUB!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


# Create a singleton instance for easy importing
settings = Settings()
