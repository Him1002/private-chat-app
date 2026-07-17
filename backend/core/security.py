"""
Security utilities and authentication module.

This module provides core security functions for authentication, password hashing,
JWT token generation/verification, and user authentication via HTTP Bearer tokens.
"""

from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.db.database import get_db
from backend.db.models import User


# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


# ================= PASSWORD UTILITIES =================
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


def verify_ws_token(token: str, db: Session) -> User:
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
    try:
        payload = decode_token(token)
        username = payload.get("sub")
        if not username:
            return None
        return db.query(User).filter(User.username == username).first()
    except JWTError:
        return None
