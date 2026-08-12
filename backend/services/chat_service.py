from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple

from sqlalchemy import or_
from sqlalchemy.orm import Session

from backend.db.models import Message, User
from backend.services.friend_service import are_friends


class NotFoundError(Exception):
    pass


class BadRequestError(Exception):
    pass


class ForbiddenError(Exception):
    pass


def _serialize_message_timestamp(timestamp: Optional[datetime]) -> Optional[str]:
    if not timestamp:
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    else:
        timestamp = timestamp.astimezone(timezone.utc)
    return timestamp.isoformat().replace("+00:00", "Z")


def _message_to_dict(message: Message, current_user: User, friend: User) -> dict:
    deleted_text = "This message was deleted"
    is_deleted = bool(message.is_deleted)
    return {
        "id": message.id,
        "sender": current_user.username if message.sender_id == current_user.id else friend.username,
        "receiver": friend.username if message.sender_id == current_user.id else current_user.username,
        "content": deleted_text if is_deleted else message.content,
        "image_url": None if is_deleted else message.image_url,
        "timestamp": _serialize_message_timestamp(message.timestamp),
        "edited_at": _serialize_message_timestamp(message.edited_at),
        "status": "read" if message.is_read else "sent",
        "is_read": message.is_read,
        "read_at": _serialize_message_timestamp(message.read_at),
        "is_deleted": is_deleted,
        "deleted_at": _serialize_message_timestamp(message.deleted_at),
    }


def get_chat_friend(db: Session, current_user: User, friend_username: str) -> User:
    friend = db.query(User).filter(User.username == friend_username).first()
    if not friend:
        raise NotFoundError("User not found")

    if not are_friends(db, current_user.id, friend.id):
        raise NotFoundError("Friend not found")

    return friend


def get_chat_messages(db: Session, current_user: User, friend_username: str) -> Tuple[User, List[Message]]:
    friend = get_chat_friend(db, current_user, friend_username)

    messages = (
        db.query(Message)
        .filter(
            or_(
                (Message.sender_id == current_user.id) & (Message.receiver_id == friend.id),
                (Message.sender_id == friend.id) & (Message.receiver_id == current_user.id),
            )
        )
        .order_by(Message.timestamp.asc())
        .all()
    )

    return friend, messages


def serialize_message_for_websocket(
    message: Message,
    current_user: User,
    friend: User,
    event_type: str = "chat",
) -> Dict:
    deleted_text = "This message was deleted"
    payload = {
        "id": message.id,
        "type": event_type,
        "sender": current_user.username if message.sender_id == current_user.id else friend.username,
        "text": deleted_text if message.is_deleted else message.content,
        "image_url": None if message.is_deleted else message.image_url,
        "timestamp": _serialize_message_timestamp(message.timestamp),
        "edited_at": _serialize_message_timestamp(message.edited_at),
        "status": "read" if message.is_read else "sent",
        "read_at": _serialize_message_timestamp(message.read_at),
        "is_deleted": bool(message.is_deleted),
        "deleted_at": _serialize_message_timestamp(message.deleted_at),
    }
    return payload


def create_message(db: Session, sender: User, receiver: User, text: Optional[str], image_url: Optional[str]) -> Message:
    if not text and not image_url:
        raise BadRequestError("Message body cannot be empty")

    message = Message(
        sender_id=sender.id,
        receiver_id=receiver.id,
        content=text,
        image_url=image_url,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(message)
    db.commit()
    db.refresh(message)

    return message


def list_conversations(db: Session, current_user: User) -> List[Dict]:
    """Return a list of conversations for the current user.

    Each conversation dict has the same shape previously returned by the controller:
    {"username", "last_message", "last_message_time", "unread_count"}
    """
    # Get friendships where the current user is the owner of the row
    friendships = (
        db.query(User)
        # We need Friend model but avoid importing it directly here to keep logic simple; query Friend via relationship
    )

    # The original controller queried Friend rows where Friend.user_id == current_user.id.
    # Reconstruct the same behavior by querying Friend via the user relationship in the DB models
    from backend.db.models import Friend

    friendships = (
        db.query(Friend)
        .filter(Friend.user_id == current_user.id, Friend.status == "accepted")
        .all()
    )

    conversations = []
    for friendship in friendships:
        friend = db.query(User).filter(User.id == friendship.friend_id).first()
        if not friend:
            continue

        last_message = (
            db.query(Message)
            .filter(
                or_(
                    (Message.sender_id == current_user.id) & (Message.receiver_id == friend.id),
                    (Message.sender_id == friend.id) & (Message.receiver_id == current_user.id),
                )
            )
            .order_by(Message.timestamp.desc())
            .first()
        )

        last_message_text = None
        if last_message is not None:
            last_message_text = "This message was deleted" if last_message.is_deleted else last_message.content

        conversations.append(
            {
                "username": friend.username,
                "last_message": last_message_text,
                "last_message_time": last_message.timestamp.isoformat() if last_message else None,
                "unread_count": 0,
            }
        )

    return conversations


def get_chat_history(db: Session, current_user: User, friend_username: str) -> List[Dict]:
    friend, messages = get_chat_messages(db, current_user, friend_username)
    return [_message_to_dict(message, current_user, friend) for message in messages]


def send_message(db: Session, current_user: User, friend_username: str, text: Optional[str], image_url: Optional[str]) -> Dict:
    friend = get_chat_friend(db, current_user, friend_username)
    message = create_message(db, current_user, friend, text, image_url)

    return _message_to_dict(message, current_user, friend)


def search_conversation_messages(
    db: Session,
    current_user: User,
    friend_username: str,
    query: str,
) -> List[Dict]:
    friend = get_chat_friend(db, current_user, friend_username)
    search_text = (query or "").strip()
    if not search_text:
        return []

    matching_messages = (
        db.query(Message)
        .filter(
            or_(
                (Message.sender_id == current_user.id) & (Message.receiver_id == friend.id),
                (Message.sender_id == friend.id) & (Message.receiver_id == current_user.id),
            ),
            Message.is_deleted.is_(False),
            Message.content.isnot(None),
            Message.content.ilike(f"%{search_text}%"),
        )
        .order_by(Message.timestamp.asc())
        .all()
    )

    return [_message_to_dict(message, current_user, friend) for message in matching_messages]


def _get_message_for_user(db: Session, current_user: User, message_id: int) -> Message:
    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        raise NotFoundError("Message not found")

    if message.sender_id != current_user.id and message.receiver_id != current_user.id:
        raise NotFoundError("Message not found")

    return message


def serialize_message_for_api(db: Session, current_user: User, message: Message) -> Dict:
    counterpart_id = message.receiver_id if message.sender_id == current_user.id else message.sender_id
    friend = db.query(User).filter(User.id == counterpart_id).first()
    if not friend:
        raise NotFoundError("User not found")
    return _message_to_dict(message, current_user, friend)


def edit_message(db: Session, current_user: User, message_id: int, text: Optional[str]) -> Message:
    message = _get_message_for_user(db, current_user, message_id)

    if message.sender_id != current_user.id:
        raise ForbiddenError("You can only edit your own messages")

    if message.is_deleted:
        raise BadRequestError("Deleted messages cannot be edited")

    existing_text = (message.content or "").strip()
    if message.image_url and not existing_text:
        raise BadRequestError("Image-only messages cannot be edited")

    next_text = (text or "").strip()
    if not next_text:
        raise BadRequestError("Message text cannot be empty")

    message.content = next_text
    message.edited_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(message)

    return message


def mark_conversation_messages_read(db: Session, current_user: User, friend: User) -> List[Message]:
    unread_messages = (
        db.query(Message.id)
        .filter(
            Message.sender_id == friend.id,
            Message.receiver_id == current_user.id,
            Message.is_read.is_(False),
        )
        .all()
    )
    message_ids = [message_id for (message_id,) in unread_messages]
    if not message_ids:
        return []

    read_at = datetime.now(timezone.utc)
    (
        db.query(Message)
        .filter(Message.id.in_(message_ids))
        .update(
            {
                Message.is_read: True,
                Message.read_at: read_at,
            },
            synchronize_session=False,
        )
    )
    db.commit()

    return db.query(Message).filter(Message.id.in_(message_ids)).all()


def mark_messages_read(db: Session, current_user: User, message_id: int) -> Dict:
    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        raise NotFoundError("Message not found")

    if message.receiver_id != current_user.id:
        raise NotFoundError("Message not found")

    if not message.is_read:
        message.is_read = True
        message.read_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(message)

    return {
        "msg": "Message marked as read",
        "id": message.id,
        "is_read": message.is_read,
        "read_at": _serialize_message_timestamp(message.read_at),
        "status": "read" if message.is_read else "sent",
    }


def delete_message(db: Session, current_user: User, message_id: int) -> Dict:
    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        raise NotFoundError("Message not found")

    if message.sender_id != current_user.id and message.receiver_id != current_user.id:
        raise NotFoundError("Message not found")

    if message.sender_id != current_user.id:
        raise ForbiddenError("You can only delete your own messages")

    if message.is_deleted:
        raise BadRequestError("Message already deleted")

    message.is_deleted = True
    message.deleted_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(message)

    return {
        "msg": "Message deleted",
        "message_id": message.id,
        "sender_id": message.sender_id,
        "receiver_id": message.receiver_id,
        "is_deleted": message.is_deleted,
        "deleted_at": _serialize_message_timestamp(message.deleted_at),
    }
