from datetime import datetime, timezone
from typing import List, Dict, Optional

from sqlalchemy.orm import Session

from backend.db.models import Message, MessageReaction, User


class NotFoundError(Exception):
    pass


class BadRequestError(Exception):
    pass


ALLOWED_EMOJIS = {"👍", "❤️", "😂", "😮", "😢", "😡", "🔥", "👏", "🎉", "💯"}


def _get_message_for_reaction(db: Session, current_user: User, message_id: int) -> Message:
    """Validate the message exists and the current user is a participant."""
    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        raise NotFoundError("Message not found")

    if message.sender_id != current_user.id and message.receiver_id != current_user.id:
        raise NotFoundError("Message not found")

    return message


def _serialize_reactions(db: Session, message_id: int) -> List[Dict]:
    """Return the current reactions for a message grouped by emoji."""
    reactions = (
        db.query(MessageReaction)
        .filter(MessageReaction.message_id == message_id)
        .all()
    )

    grouped: Dict[str, Dict] = {}
    for r in reactions:
        if r.emoji not in grouped:
            grouped[r.emoji] = {"emoji": r.emoji, "count": 0, "user_ids": []}
        grouped[r.emoji]["count"] += 1
        grouped[r.emoji]["user_ids"].append(r.user_id)

    return list(grouped.values())


def _serialize_reactions_with_usernames(db: Session, message_id: int) -> List[Dict]:
    """Return reactions grouped by emoji, with usernames instead of user_ids."""
    reactions = (
        db.query(MessageReaction)
        .filter(MessageReaction.message_id == message_id)
        .all()
    )

    # Collect unique user_ids and batch-load usernames
    user_ids = list({r.user_id for r in reactions})
    users = {}
    if user_ids:
        user_rows = db.query(User).filter(User.id.in_(user_ids)).all()
        users = {u.id: u.username for u in user_rows}

    grouped: Dict[str, Dict] = {}
    for r in reactions:
        if r.emoji not in grouped:
            grouped[r.emoji] = {"emoji": r.emoji, "count": 0, "user_ids": [], "usernames": []}
        grouped[r.emoji]["count"] += 1
        grouped[r.emoji]["user_ids"].append(r.user_id)
        grouped[r.emoji]["usernames"].append(users.get(r.user_id, "unknown"))

    return list(grouped.values())


def get_reactions_for_message(db: Session, message_id: int) -> List[Dict]:
    """Return reactions for a single message with usernames."""
    return _serialize_reactions_with_usernames(db, message_id)


def get_reactions_for_messages(db: Session, message_ids: List[int]) -> Dict[int, List[Dict]]:
    """Batch fetch reactions for multiple messages, keyed by message_id."""
    if not message_ids:
        return {}

    reactions = (
        db.query(MessageReaction)
        .filter(MessageReaction.message_id.in_(message_ids))
        .all()
    )

    # Collect unique user_ids and batch-load usernames
    user_ids = list({r.user_id for r in reactions})
    users = {}
    if user_ids:
        user_rows = db.query(User).filter(User.id.in_(user_ids)).all()
        users = {u.id: u.username for u in user_rows}

    result: Dict[int, Dict[str, Dict]] = {}
    for r in reactions:
        if r.message_id not in result:
            result[r.message_id] = {}
        if r.emoji not in result[r.message_id]:
            result[r.message_id][r.emoji] = {"emoji": r.emoji, "count": 0, "user_ids": [], "usernames": []}
        result[r.message_id][r.emoji]["count"] += 1
        result[r.message_id][r.emoji]["user_ids"].append(r.user_id)
        result[r.message_id][r.emoji]["usernames"].append(users.get(r.user_id, "unknown"))

    return {mid: list(grouped.values()) for mid, grouped in result.items()}


def add_reaction(db: Session, current_user: User, message_id: int, emoji: str) -> List[Dict]:
    """Add a reaction to a message. Returns the updated reaction list for the message."""
    if emoji not in ALLOWED_EMOJIS:
        raise BadRequestError("Invalid emoji")

    message = _get_message_for_reaction(db, current_user, message_id)

    # Check if the reaction already exists (duplicate prevention)
    existing = (
        db.query(MessageReaction)
        .filter(
            MessageReaction.message_id == message.id,
            MessageReaction.user_id == current_user.id,
            MessageReaction.emoji == emoji,
        )
        .first()
    )
    if existing:
        # Silently ignore duplicates
        return _serialize_reactions_with_usernames(db, message.id)

    reaction = MessageReaction(
        message_id=message.id,
        user_id=current_user.id,
        emoji=emoji,
        created_at=datetime.now(timezone.utc),
    )
    db.add(reaction)
    db.commit()

    return _serialize_reactions_with_usernames(db, message.id)


def remove_reaction(db: Session, current_user: User, message_id: int, emoji: str) -> List[Dict]:
    """Remove a reaction from a message. Returns the updated reaction list for the message."""
    message = _get_message_for_reaction(db, current_user, message_id)

    reaction = (
        db.query(MessageReaction)
        .filter(
            MessageReaction.message_id == message.id,
            MessageReaction.user_id == current_user.id,
            MessageReaction.emoji == emoji,
        )
        .first()
    )
    if not reaction:
        raise NotFoundError("Reaction not found")

    db.delete(reaction)
    db.commit()

    return _serialize_reactions_with_usernames(db, message.id)
