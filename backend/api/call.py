"""
Call API router module for ChatSpic V2 Voice & Video Calling.

Provides authenticated endpoints for WebRTC calling configuration.
"""
from typing import Dict, Any
from fastapi import APIRouter, Depends

from backend.core.config import settings
from backend.core.security import get_current_user
from backend.db.models import User

router = APIRouter(prefix="/call", tags=["call"])


@router.get("/config")
def get_call_config(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Return WebRTC ICE server configuration for authenticated users.

    Strict security guarantees:
    - Requires authenticated user via HTTP Bearer token.
    - Exposes only client-safe ICE server details (STUN/TURN URLs and username).
    - In compliance with project security constraints, credentials and internal secrets
      are never exposed through this or any API response.
    """
    return {
        "ice_servers": settings.get_ice_servers(),
    }
