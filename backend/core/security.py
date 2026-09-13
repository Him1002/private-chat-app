"""
Security utilities and authentication module.

This module provides core security functions for authentication, password hashing,
JWT token generation/verification, and user authentication via HTTP Bearer tokens.
"""

import mimetypes
import threading
import time
from collections import defaultdict
from jose import jwt, JWTError
from passlib.context import CryptContext
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta

# Ensure standard web MIME types across all OS platforms (fixes Windows registry mapping of .js to text/plain)
mimetypes.init()
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("application/javascript", ".mjs")
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.db.database import get_db
from backend.db.models import User


# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


# ================= PASSWORD UTILITIES =================
MIN_PASSWORD_BYTES: int = 8
MAX_PASSWORD_BYTES: int = 72


class PasswordValidationError(ValueError):
    """Raised when a candidate password violates the password policy."""
    pass


def validate_new_password(password: str) -> None:
    """Validate a candidate password against the password policy.

    Policy rules:
    - Minimum length: 8 UTF-8 bytes.
    - Maximum length: 72 UTF-8 bytes (hard limit for bcrypt hashing).
    - Measured strictly by UTF-8 byte count, not Python character count.
    - Explicitly rejects passwords exceeding limits without truncation.
    """
    if not isinstance(password, str):
        raise PasswordValidationError("Password must be a string")

    try:
        encoded = password.encode("utf-8")
    except UnicodeEncodeError:
        raise PasswordValidationError("Password must be valid UTF-8")

    byte_len = len(encoded)
    if byte_len < MIN_PASSWORD_BYTES:
        raise PasswordValidationError(f"Password must be at least {MIN_PASSWORD_BYTES} characters long")
    if byte_len > MAX_PASSWORD_BYTES:
        raise PasswordValidationError(f"Password exceeds maximum allowed length of {MAX_PASSWORD_BYTES} bytes (received {byte_len} bytes)")


def hash_password(plain: str) -> str:
    """Hash a plain-text password using bcrypt.

    Args:
        plain: The plain-text password to hash

    Returns:
        The bcrypt password hash
    """
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """
    Verify a plain-text password against its hashed version.
    
    Args:
        plain: The plain-text password to verify
        hashed: The hashed password to compare against
        
    Returns:
        True if the password matches, False otherwise
    """
    return pwd_context.verify(plain, hashed)


# Constant-time dummy hash for timing attack mitigation when username is nonexistent
DUMMY_HASH: str = pwd_context.hash("timing-defense-dummy-nonexistent-user-hash")


# ================= AUTHENTICATION RATE LIMITING =================
def get_client_ip(request: Request) -> str:
    """Extract authoritative client IP from request.client.host for single-instance deployment."""
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


class InMemoryRateLimiter:
    """Lightweight, thread-safe in-process sliding-window rate limiter."""

    def __init__(self, max_attempts: int, window_seconds: int):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def _clean_window(self, key: str, now: float) -> List[float]:
        cutoff = now - self.window_seconds
        valid = [t for t in self._attempts[key] if t > cutoff]
        self._attempts[key] = valid
        return valid

    def is_rate_limited(self, key: str) -> Tuple[bool, int]:
        """Check if key has reached or exceeded max attempts in the current window.

        Returns:
            (is_limited, retry_after_seconds)
        """
        now = time.monotonic()
        with self._lock:
            attempts = self._clean_window(key, now)
            if len(attempts) >= self.max_attempts:
                oldest = min(attempts)
                retry_after = max(1, int(self.window_seconds - (now - oldest)))
                return True, retry_after
            return False, 0

    def record_attempt(self, key: str) -> None:
        """Record an attempt for key at the current monotonic timestamp."""
        now = time.monotonic()
        with self._lock:
            self._clean_window(key, now)
            self._attempts[key].append(now)

    def reset_key(self, key: str) -> None:
        """Reset rate limit history for a specific key."""
        with self._lock:
            self._attempts.pop(key, None)

    def reset(self) -> None:
        """Reset all rate limiter records (used for test isolation)."""
        with self._lock:
            self._attempts.clear()


failed_login_limiter = InMemoryRateLimiter(max_attempts=5, window_seconds=60)
registration_limiter = InMemoryRateLimiter(max_attempts=10, window_seconds=60)


def reset_auth_rate_limiters() -> None:
    """Reset all authentication rate limiters (used for test isolation)."""
    failed_login_limiter.reset()
    registration_limiter.reset()




# ================= JWT TOKEN UTILITIES =================
def create_access_token(data: dict, expires_delta: timedelta) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Dictionary of claims to encode (typically {"sub": username})
        expires_delta: How long the token should be valid for
        
    Returns:
        An encoded JWT token string
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT token.
    
    Args:
        token: The JWT token to decode
        
    Returns:
        The decoded payload as a dictionary
        
    Raises:
        JWTError: If the token is invalid or expired
    """
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


# ================= USER AUTHENTICATION =================
def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Extract and validate the current user from the HTTP Bearer token.
    
    This dependency is used on protected endpoints to ensure the request
    includes a valid JWT token and retrieve the associated user.
    
    Args:
        creds: The HTTP Bearer credentials from the request
        db: Database session for user lookup
        
    Returns:
        The User object associated with the token
        
    Raises:
        HTTPException: If the token is invalid or the user doesn't exist
    """
    try:
        token = creds.credentials
        payload = decode_token(token)
        username = payload.get("sub")
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=401)
        return user
    except JWTError:
        raise HTTPException(status_code=401)


def verify_ws_token(token: str, db: Session) -> Optional[User]:
    """
    Verify a JWT token for WebSocket connections.
    
    Similar to get_current_user but designed for WebSocket connections
    which don't have the Depends framework available.
    
    Args:
        token: The JWT token to verify
        db: Database session for user lookup
        
    Returns:
        The User object if token is valid, None otherwise
    """
    if not token or not isinstance(token, str):
        return None

    try:
        payload = decode_token(token)
    except JWTError:
        return None

    username = payload.get("sub")
    if not username or not isinstance(username, str):
        return None

    return db.query(User).filter(User.username == username).first()


# ================= HTTP SECURITY MIDDLEWARE =================
class SecurityHeadersMiddleware:
    """ASGI middleware adding HTTP security headers to HTTP responses.

    Injects non-breaking security headers (X-Content-Type-Options,
    Referrer-Policy, X-Frame-Options) on normal HTTP responses.
    WebSockets (scope['type'] == 'websocket') pass through unmodified.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                existing = {k.decode("latin-1").lower() for k, _ in headers}
                if "x-content-type-options" not in existing:
                    headers.append((b"x-content-type-options", b"nosniff"))
                if "referrer-policy" not in existing:
                    headers.append((b"referrer-policy", b"strict-origin-when-cross-origin"))
                if "x-frame-options" not in existing:
                    headers.append((b"x-frame-options", b"DENY"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_security_headers)
