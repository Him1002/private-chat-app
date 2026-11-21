"""Push notifications API router for ChatSpic (V2 Task R7).

Exposes endpoints for obtaining the VAPID public key and registering or
removing browser push subscriptions for the authenticated user.
"""
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.security import get_current_user
from backend.db.database import get_db
from backend.db.models import User
from backend.services import push_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/push", tags=["push"])


class PushSubscriptionKeys(BaseModel):
    p256dh: str = Field(..., description="Client P-256 public key")
    auth: str = Field(..., description="Client authentication secret")


class PushSubscriptionCreate(BaseModel):
    endpoint: str = Field(..., description="Push service delivery endpoint URL")
    keys: PushSubscriptionKeys


@router.get("/vapid-public-key")
def get_vapid_public_key(current_user: User = Depends(get_current_user)):
    """Return the VAPID public key needed by the browser to subscribe to push.

    Security: Never exposes VAPID_PRIVATE_KEY or credentials.
    """
    return {
        "public_key": settings.VAPID_PUBLIC_KEY,
        "enabled": settings.is_web_push_configured,
    }


@router.post("/subscribe", status_code=status.HTTP_200_OK)
def subscribe(
    data: PushSubscriptionCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Register or update a push subscription for the authenticated user.

    Security: Associates subscription strictly with the authenticated current_user.
    A user cannot register or modify subscriptions for another user.
    """
    endpoint = data.endpoint.strip() if data.endpoint else ""
    p256dh = data.keys.p256dh.strip() if data.keys.p256dh else ""
    auth = data.keys.auth.strip() if data.keys.auth else ""

    if not endpoint or not (endpoint.startswith("https://") or endpoint.startswith("http://localhost") or endpoint.startswith("http://127.0.0.1")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid push service endpoint; must be a secure URL",
        )
    if not p256dh or not auth:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required cryptographic subscription keys (p256dh, auth)",
        )

    try:
        push_service.save_subscription(db, current_user, endpoint, p256dh, auth)
        return {"status": "ok", "message": "Push subscription registered successfully"}
    except Exception as exc:
        logger.error("Error saving push subscription for user %s: %s", current_user.username, exc, exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to save push subscription")


@router.post("/unsubscribe", status_code=status.HTTP_200_OK)
def unsubscribe(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Remove the push subscription for the authenticated user."""
    removed = push_service.remove_subscription(db, current_user)
    return {"status": "ok", "removed": removed}


@router.get("/status")
def push_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Check whether Web Push is enabled on the server and if the user has an active subscription."""
    sub = push_service.get_subscription(db, current_user.id)
    return {
        "enabled": settings.is_web_push_configured,
        "subscribed": bool(sub is not None),
    }
