from datetime import datetime, timezone
from typing import List, Dict, Optional

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


def _message_to_dict(message: Message, current_user: User, friend: User) -> dict:
    return {
        "id": message.id,
        "sender": current_user.username if message.sender_id == current_user.id else friend.username,
        "receiver": friend.username if message.sender_id == current_user.id else current_user.username,
        "content": message.content,
        "image_url": message.image_url,
        "timestamp": message.timestamp.isoformat() if message.timestamp else None,
    }


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

        conversations.append(
            {
                "username": friend.username,
                "last_message": last_message.content if last_message else None,
                "last_message_time": last_message.timestamp.isoformat() if last_message else None,
                "unread_count": 0,
            }
        )

    return conversations


def get_chat_history(db: Session, current_user: User, friend_username: str) -> List[Dict]:
    friend = db.query(User).filter(User.username == friend_username).first()
    if not friend:
        raise NotFoundError("User not found")

    if not are_friends(db, current_user.id, friend.id):
        raise NotFoundError("Friend not found")

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

    return [_message_to_dict(message, current_user, friend) for message in messages]


def send_message(db: Session, current_user: User, friend_username: str, text: Optional[str], image_url: Optional[str]) -> Dict:
    friend = db.query(User).filter(User.username == friend_username).first()
    if not friend:
        raise NotFoundError("User not found")

    if not are_friends(db, current_user.id, friend.id):
        raise NotFoundError("Friend not found")

    if not text and not image_url:
        raise BadRequestError("Message body cannot be empty")

    message = Message(
        sender_id=current_user.id,
        receiver_id=friend.id,
        content=text,
        image_url=image_url,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(message)
    db.commit()
    db.refresh(message)

    return _message_to_dict(message, current_user, friend)


def mark_messages_read(db: Session, current_user: User, message_id: int) -> Dict:
    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        raise NotFoundError("Message not found")

    if message.receiver_id != current_user.id and message.sender_id != current_user.id:
        raise NotFoundError("Message not found")

    # The original controller did not persist a read flag. Preserve behaviour.
    return {"msg": "Message marked as read"}


def delete_message(db: Session, current_user: User, message_id: int) -> Dict:
    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        raise NotFoundError("Message not found")

    if message.sender_id != current_user.id and message.receiver_id != current_user.id:
        raise NotFoundError("Message not found")

    db.delete(message)
    db.commit()

    return {"msg": "Message deleted"}
