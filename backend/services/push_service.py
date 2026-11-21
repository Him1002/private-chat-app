"""Push notification service module for ChatSpic (V2 Task R7).

Centralizes Web Push subscription persistence, preview sanitization,
authoritative active-conversation suppression, and isolated background
delivery.
"""
import asyncio
import json
import logging
import re
from datetime import datetime, UTC
from typing import Optional, Dict, Any

from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.db.database import SessionLocal
from backend.db.models import PushSubscription, User, Message
from backend.services.upload_service import (
    is_voice_file,
    is_video_file,
    is_document_file,
)

logger = logging.getLogger(__name__)

# Try importing pywebpush safely
try:
    import pywebpush
    from pywebpush import webpush, WebPushException
except ImportError:  # pragma: no cover
    pywebpush = None
    webpush = None
    WebPushException = Exception


# ==============================================================================
# 1. Subscription Management (CRUD)
# ==============================================================================

def save_subscription(
    db: Session,
    user: User,
    endpoint: str,
    p256dh: str,
    auth: str,
) -> PushSubscription:
    """Create or update the push subscription for the authenticated user.

    Enforces the single-account / single-active-device constraint by upserting
    the single subscription associated with user.id, and disassociating any
    stale subscription records with the same endpoint belonging to other users
    (multi-account browser profile switching).
    """
    if not endpoint or not isinstance(endpoint, str) or not endpoint.strip():
        raise ValueError("Invalid push subscription endpoint")
    if not p256dh or not isinstance(p256dh, str) or not p256dh.strip():
        raise ValueError("Invalid push subscription p256dh key")
    if not auth or not isinstance(auth, str) or not auth.strip():
        raise ValueError("Invalid push subscription auth key")

    clean_endpoint = endpoint.strip()
    clean_p256dh = p256dh.strip()
    clean_auth = auth.strip()

    # Remove any existing subscription records for other users with the same endpoint
    # to prevent notification leakage across account switching on the same browser profile.
    db.query(PushSubscription).filter(
        PushSubscription.endpoint == clean_endpoint,
        PushSubscription.user_id != user.id,
    ).delete(synchronize_session=False)

    sub = db.query(PushSubscription).filter(PushSubscription.user_id == user.id).first()
    now = datetime.now(UTC)
    if sub:
        sub.endpoint = clean_endpoint
        sub.p256dh = clean_p256dh
        sub.auth = clean_auth
        sub.updated_at = now
    else:
        sub = PushSubscription(
            user_id=user.id,
            endpoint=clean_endpoint,
            p256dh=clean_p256dh,
            auth=clean_auth,
            created_at=now,
            updated_at=now,
        )
        db.add(sub)

    db.commit()
    db.refresh(sub)
    return sub


def remove_subscription(db: Session, user: User) -> bool:
    """Remove the push subscription for the authenticated user."""
    sub = db.query(PushSubscription).filter(PushSubscription.user_id == user.id).first()
    if sub:
        db.delete(sub)
        db.commit()
        return True
    return False


def get_subscription(db: Session, user_id: int) -> Optional[PushSubscription]:
    """Retrieve push subscription for a user by user_id."""
    return db.query(PushSubscription).filter(PushSubscription.user_id == user_id).first()


def delete_subscription_by_id(db: Session, subscription_id: int) -> bool:
    """Delete an expired or invalid subscription by primary key."""
    sub = db.query(PushSubscription).filter(PushSubscription.id == subscription_id).first()
    if sub:
        db.delete(sub)
        db.commit()
        logger.info("Cleaned up expired/invalid push subscription id=%s", subscription_id)
        return True
    return False


# ==============================================================================
# 2. Content Sanitization & Payload Formatting
# ==============================================================================

def sanitize_preview_text(text: Optional[str], max_length: int = 120) -> str:
    """Sanitize and truncate text preview for push notifications.

    - Strips script and style elements with their contents
    - Strips HTML tags
    - Replaces newlines, tabs, and control characters with single space
    - Truncates to max_length with ellipsis
    - Never leaks raw HTML or control sequences
    """
    if not text or not isinstance(text, str):
        return ""

    # Strip script and style blocks including their contents
    clean = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", text, flags=re.DOTALL | re.IGNORECASE)
    # Strip HTML tags
    clean = re.sub(r"<[^>]*>", "", clean)
    # Strip control characters, carriage returns, newlines, tabs
    clean = re.sub(r"[\r\n\t\x00-\x1f\x7f]+", " ", clean).strip()
    clean = re.sub(r"\s+", " ", clean)

    if len(clean) > max_length:
        clean = clean[:max_length].rstrip() + "..."
    return clean


def format_push_payload(sender: User, message: Message) -> dict:
    """Format notification payload according to ChatSpic R7 requirements.

    Requirements:
    - Sender display name in notification title
    - Voice messages preview: EXACT string "🎙️ Voice message"
    - Sanitized text preview
    - No JWTs, credentials, or tokens in data
    - Safe conversation identifier in data
    - Tag for browser/OS grouping
    """
    sender_title = sender.display_name if sender.display_name and sender.display_name.strip() else sender.username

    # Determine message preview body
    media_url = message.image_url if message.image_url else None
    if media_url and is_voice_file(media_url):
        body = "🎙️ Voice message"
    elif media_url and is_video_file(media_url):
        body = sanitize_preview_text(message.content) if message.content else "🎥 Video"
    elif media_url and is_document_file(media_url):
        body = sanitize_preview_text(message.content) if message.content else "📎 File"
    elif media_url:
        body = sanitize_preview_text(message.content) if message.content else "📷 Photo"
    else:
        body = sanitize_preview_text(message.content)

    return {
        "title": sender_title,
        "body": body,
        "tag": f"chat-{sender.username}",
        "data": {
            "conversation": sender.username,
            "url": "/",
            "message_id": message.id,
        },
        "icon": "/static/favicon.ico",
        "badge": "/static/favicon.ico",
    }


# ==============================================================================
# 3. Authoritative Active-Conversation Suppression
# ==============================================================================

def should_suppress_push(recipient_id: int, sender_id: int) -> bool:
    """Determine if a push notification should be suppressed.

    Authoritative check against server-side WebSocket state:
    Returns True if recipient is actively connected and viewing the DM room
    with sender in a foreground/visible window.
    """
    if recipient_id == sender_id:
        return True

    try:
        from backend.realtime.websocket import is_user_actively_viewing
        return is_user_actively_viewing(recipient_id, sender_id)
    except Exception as exc:
        logger.debug("Error checking active conversation suppression: %s", exc)
        return False


# ==============================================================================
# 4. Push Delivery & Background Execution
# ==============================================================================

def send_webpush(
    subscription_info: dict,
    payload_str: str,
    subscription_id: Optional[int] = None,
) -> bool:
    """Send a Web Push notification to a single browser subscription.

    Handles VAPID signing, encryption, and automatic cleanup of expired
    subscriptions (404 / 410 Gone).
    Never logs private keys or notification payload bodies.
    """
    if not settings.is_web_push_configured:
        logger.debug("Web Push skipped: VAPID keys not configured")
        return False

    if pywebpush is None or webpush is None:  # pragma: no cover
        logger.warning("pywebpush is not installed; cannot deliver Web Push")
        return False

    try:
        webpush(
            subscription_info=subscription_info,
            data=payload_str,
            vapid_private_key=settings.VAPID_PRIVATE_KEY,
            vapid_claims={"sub": settings.VAPID_CLAIMS_SUB},
            timeout=5,
        )
        logger.info("Web Push notification sent successfully to endpoint=%s...", subscription_info.get("endpoint", "")[:30])
        return True
    except WebPushException as exc:
        status_code = getattr(getattr(exc, "response", None), "status_code", None)
        logger.warning("WebPushException encountered (status_code=%s): %s", status_code, exc)
        # HTTP 404 (Not Found) or 410 (Gone) indicates the subscription has expired or was revoked
        if status_code in (404, 410) and subscription_id:
            _cleanup_subscription_background(subscription_id)
        return False
    except Exception as exc:
        status_code = getattr(getattr(exc, "response", None), "status_code", None)
        logger.warning("Unexpected error delivering Web Push (status_code=%s): %s", status_code, exc)
        if status_code in (404, 410) and subscription_id:
            _cleanup_subscription_background(subscription_id)
        return False


def _cleanup_subscription_background(subscription_id: int):
    """Clean up expired subscription using a dedicated short-lived DB session."""
    db = SessionLocal()
    try:
        delete_subscription_by_id(db, subscription_id)
    except Exception as exc:
        logger.debug("Failed to clean up subscription id=%s: %s", subscription_id, exc)
    finally:
        db.close()


def deliver_push_for_message_background(sender_id: int, recipient_id: int, message_id: int):
    """Execute push delivery logic in background using a dedicated short-lived DB session.

    Ensures zero session reuse from request lifecycle.
    """
    if sender_id == recipient_id:
        return

    if not settings.is_web_push_configured:
        return

    # Check suppression before DB work if possible
    if should_suppress_push(recipient_id, sender_id):
        logger.debug("Web Push suppressed: recipient %s is actively viewing conversation with %s", recipient_id, sender_id)
        return

    db = SessionLocal()
    subscription_info = None
    subscription_id = None
    payload_str = None
    try:
        sub = db.query(PushSubscription).filter(PushSubscription.user_id == recipient_id).first()
        if not sub:
            return

        sender = db.query(User).filter(User.id == sender_id).first()
        message = db.query(Message).filter(Message.id == message_id).first()
        if not sender or not message:
            return

        payload = format_push_payload(sender, message)
        payload_str = json.dumps(payload)
        subscription_info = {
            "endpoint": sub.endpoint,
            "keys": {
                "p256dh": sub.p256dh,
                "auth": sub.auth,
            }
        }
        subscription_id = sub.id
    except Exception as exc:
        logger.warning("Error preparing push notification in background: %s", exc)
        return
    finally:
        db.close()

    if subscription_info and payload_str:
        send_webpush(subscription_info, payload_str, subscription_id)


def trigger_message_push(sender_id: int, recipient_id: int, message_id: int):
    """Asynchronously schedule push notification delivery without blocking calling thread."""
    if sender_id == recipient_id:
        return
    if not settings.is_web_push_configured:
        return

    try:
        loop = asyncio.get_running_loop()
        loop.run_in_executor(None, deliver_push_for_message_background, sender_id, recipient_id, message_id)
    except RuntimeError:
        # No running event loop (e.g. called in synchronous test context or worker thread)
        # Execute directly in safe isolated thread
        import threading
        t = threading.Thread(
            target=deliver_push_for_message_background,
            args=(sender_id, recipient_id, message_id),
            daemon=True,
        )
        t.start()
