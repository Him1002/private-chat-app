"""
Logging configuration module for ChatSpic.

Provides standard-library-based logging suitable for single-process V1 deployment.
Includes sensitive data redaction as defense-in-depth, idempotent setup, and
sensible log levels.
"""
import logging
import os
import re
import sys
from typing import Optional, List, Tuple

LOG_FORMAT: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"


class SensitiveDataFilter(logging.Filter):
    """Defense-in-depth logging filter that sanitizes known sensitive patterns.

    Redacts:
    - JWT tokens
    - Bearer authorization tokens
    - Plaintext passwords in common key/value or JSON contexts
    - Bcrypt password hashes

    Application code is still independently required to never pass sensitive
    values (passwords, hashes, tokens, secrets) to loggers.
    """

    PATTERNS: List[Tuple[re.Pattern, str]] = [
        # JWT tokens (three base64url segments separated by dots)
        (
            re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
            "[REDACTED_JWT]",
        ),
        # Authorization Bearer tokens
        (
            re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*"),
            "Bearer [REDACTED_TOKEN]",
        ),
        # Password keys in JSON or key=value formats
        (
            re.compile(r'(?i)(["\']?password["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])'),
            r"\1[REDACTED_PASSWORD]\3",
        ),
        # Bcrypt password hashes ($2a$, $2b$, $2y$)
        (
            re.compile(r"\$2[aby]?\$\d{1,2}\$[A-Za-z0-9./]{53}"),
            "[REDACTED_HASH]",
        ),
    ]

    def _sanitize(self, val: str) -> str:
        for pattern, replacement in self.PATTERNS:
            val = pattern.sub(replacement, val)
        return val

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self._sanitize(record.msg)

        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: self._sanitize(v) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    self._sanitize(v) if isinstance(v, str) else v
                    for v in record.args
                )
            elif isinstance(record.args, list):
                record.args = [
                    self._sanitize(v) if isinstance(v, str) else v
                    for v in record.args
                ]

        return True


def get_configured_log_level() -> int:
    """Determine log level from settings or LOG_LEVEL environment variable, defaulting to INFO."""
    try:
        from backend.core.config import settings
        level_str = getattr(settings, "LOG_LEVEL", "")
    except Exception:
        level_str = ""

    if not level_str:
        level_str = os.getenv("LOG_LEVEL", "").strip().upper()

    if level_str:
        level = getattr(logging, level_str, None)
        if isinstance(level, int):
            return level
    return logging.INFO


def setup_logging(level: Optional[int] = None) -> logging.Logger:
    """Configure standard library logging for the ChatSpic application.

    - Uses standard library StreamHandler on sys.stdout.
    - Idempotent: does not create duplicate handlers if called repeatedly.
    - Attaches SensitiveDataFilter for defense-in-depth sanitization.
    - Silences verbose third-party loggers (passlib, multipart).

    Returns:
        The root logger configured for the application.
    """
    if level is None:
        level = get_configured_log_level()

    formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    redaction_filter = SensitiveDataFilter()

    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.disabled = False
    for name, logger_obj in logging.root.manager.loggerDict.items():
        if isinstance(logger_obj, logging.Logger):
            logger_obj.disabled = False

    # Check for existing custom handler to maintain idempotency
    existing_handler = None
    for handler in root_logger.handlers:
        if getattr(handler, "_chatspic_handler", False):
            existing_handler = handler
            break

    if existing_handler:
        existing_handler.setLevel(level)
        existing_handler.setFormatter(formatter)
    else:
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setLevel(level)
        stream_handler.setFormatter(formatter)
        stream_handler.addFilter(redaction_filter)
        stream_handler._chatspic_handler = True
        root_logger.addHandler(stream_handler)

    # Ensure backend logger namespace inherits level and filter
    backend_logger = logging.getLogger("backend")
    backend_logger.setLevel(level)

    # Keep third-party loggers from spamming normal application logs
    logging.getLogger("passlib").setLevel(logging.WARNING)
    logging.getLogger("multipart").setLevel(logging.WARNING)

    return root_logger
