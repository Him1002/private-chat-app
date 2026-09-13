"""
Authentication and registration service module.

This module encapsulates business logic for user authentication, registration,
password validation, rate limiting checks, and anti-enumeration timing defenses.
"""

from datetime import datetime, timedelta, UTC
from typing import Optional
from fastapi import HTTPException
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.security import (
    create_access_token,
    failed_login_limiter,
    hash_password,
    registration_limiter,
    validate_new_password,
    verify_password,
    DUMMY_HASH,
    PasswordValidationError,
)
from backend.db.models import User


def authenticate_user(db: Session, username: str, password: str, client_ip: str) -> str:
    """
    Authenticate a user by username and password.

    - Enforces rate limiting keyed by client IP, primarily triggered by failed attempts.
    - Prevents account enumeration timing attacks via constant-time verification.
    - Preserves existing passwords: does not enforce new password policy on login.
    - Does not modify user.password_hash upon login.
    - Resets failed login count for client_ip upon successful authentication.

    Returns:
        Encoded JWT access token string.

    Raises:
        HTTPException(429): If client IP has exceeded failed login threshold.
        HTTPException(401): If credentials are invalid.
    """
    # 1. Rate limit check (triggered if threshold of failed attempts was reached)
    is_limited, retry_after = failed_login_limiter.is_rate_limited(client_ip)
    if is_limited:
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    # 2. Lookup user
    user = db.query(User).filter(User.username == username).first()

    # 3. Defensive constant-time verification
    if not user:
        # Nonexistent user: verify against dummy hash to prevent timing side-channel
        verify_password(password, DUMMY_HASH)
        failed_login_limiter.record_attempt(client_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # 4. Verify password
    if not verify_password(password, user.password_hash):
        failed_login_limiter.record_attempt(client_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # 5. Successful login: reset failed attempts for this client IP
    failed_login_limiter.reset_key(client_ip)

    # 6. Generate access token
    token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return token


def register_user(db: Session, username: str, password: str, client_ip: str) -> User:
    """
    Register a new user account.

    - Enforces lightweight registration abuse protection keyed by client IP.
    - Checks rate limit before expensive password hashing or DB operations.
    - Enforces the password policy (min 8 bytes, max 72 UTF-8 bytes).
    - Checks for duplicate username.
    - Hashes password using bcrypt.

    Returns:
        The newly created User entity.

    Raises:
        HTTPException(429): If client IP exceeded registration rate limit.
        HTTPException(400): If username or password violates validation rules.
    """
    # 1. Rate limit check before expensive operations
    is_limited, retry_after = registration_limiter.is_rate_limited(client_ip)
    if is_limited:
        raise HTTPException(
            status_code=429,
            detail="Too many registration attempts. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    # 2. Record registration attempt
    registration_limiter.record_attempt(client_ip)

    # 3. Validate username
    if not username or not username.strip():
        raise HTTPException(status_code=400, detail="Username cannot be empty")

    # 4. Validate password policy
    try:
        validate_new_password(password)
    except PasswordValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # 5. Check if username already exists
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")

    # 6. Create and persist user with hashed password
    new_user = User(
        username=username,
        password_hash=hash_password(password),
        last_seen=datetime.now(UTC),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user
