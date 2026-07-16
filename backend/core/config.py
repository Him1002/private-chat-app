"""
Application configuration module.

This module centralizes all application configuration values including
security settings, JWT configuration, and file upload paths.
"""


class Settings:
    """Application settings container."""

    # ================= SECURITY =================
    SECRET_KEY: str = "super-secret-key-change-later"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ================= FILE PATHS =================
    UPLOADS_DIR: str = "uploads"
    STATIC_DIR: str = "static"


# Create a singleton instance for easy importing
settings = Settings()
