from datetime import datetime, UTC
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.orm import Session

from backend.core.security import get_current_user
from backend.db.database import get_db
from backend.db.models import Friend, Message, User

router = APIRouter()


class MessageCreate(BaseModel):
    text: Optional[str] = None
    image_url: Optional[str] = None


def _ensure_friendship(db: Session, current_user: User, friend: User) -> None:
    is_friend = (
        db.query(Friend)
        .filter(
            ((Friend.user_id == current_user.id) & (Friend.friend_id == friend.id))
            | ((Friend.user_id == friend.id) & (Friend.friend_id == current_user.id)),
            Friend.status == "accepted",
        )
        .first()
        is not None
    )

    if not is_friend:
        raise HTTPException(status_code=404, detail="Friend not found")


def _message_to_dict(message: Message, current_user: User, friend: User) -> dict:
    return {
        "id": message.id,
        "sender": current_user.username if message.sender_id == current_user.id else friend.username,
        "receiver": friend.username if message.sender_id == current_user.id else current_user.username,
        "content": message.content,
        "image_url": message.image_url,
        "timestamp": message.timestamp.isoformat() if message.timestamp else None,
    }


@router.get("/chats")
@router.get("/conversations")
@router.get("/chat/list")
@router.get("/conversation/list")
def list_conversations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
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


@router.get("/chat/history/{friend_username}")
@router.get("/messages/{friend_username}")
@router.get("/chat/{friend_username}")
def get_chat_history(
    friend_username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    friend = db.query(User).filter(User.username == friend_username).first()
    if not friend:
        raise HTTPException(status_code=404, detail="User not found")

    _ensure_friendship(db, current_user, friend)

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


@router.post("/messages/{friend_username}")
@router.post("/chat/send/{friend_username}")
@router.post("/message/{friend_username}")
async def send_message(
    friend_username: str,
    data: MessageCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    friend = db.query(User).filter(User.username == friend_username).first()
    if not friend:
        raise HTTPException(status_code=404, detail="User not found")

    _ensure_friendship(db, current_user, friend)

    if not data.text and not data.image_url:
        raise HTTPException(status_code=400, detail="Message body cannot be empty")

    message = Message(
        sender_id=current_user.id,
        receiver_id=friend.id,
        content=data.text,
        image_url=data.image_url,
        timestamp=datetime.now(UTC),
    )
    db.add(message)
    db.commit()
    db.refresh(message)

    return _message_to_dict(message, current_user, friend)


@router.post("/messages/{message_id}/read")
@router.post("/chat/messages/{message_id}/read")
def mark_messages_read(
    message_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    if message.receiver_id != current_user.id and message.sender_id != current_user.id:
        raise HTTPException(status_code=404, detail="Message not found")

    return {"msg": "Message marked as read"}


@router.delete("/messages/{message_id}")
@router.delete("/chat/messages/{message_id}")
def delete_message(
    message_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    if message.sender_id != current_user.id and message.receiver_id != current_user.id:
        raise HTTPException(status_code=404, detail="Message not found")

    db.delete(message)
    db.commit()

    return {"msg": "Message deleted"}
