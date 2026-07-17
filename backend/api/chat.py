from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.core.security import get_current_user
from backend.db.database import get_db
from backend.db.models import User
from backend.services import chat_service

router = APIRouter()


class MessageCreate(BaseModel):
    text: Optional[str] = None
    image_url: Optional[str] = None


@router.get("/chats")
@router.get("/conversations")
@router.get("/chat/list")
@router.get("/conversation/list")
def list_conversations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        return chat_service.list_conversations(db, current_user)
    except chat_service.NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/chat/history/{friend_username}")
@router.get("/messages/{friend_username}")
@router.get("/chat/{friend_username}")
def get_chat_history(
    friend_username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        return chat_service.get_chat_history(db, current_user, friend_username)
    except chat_service.NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/messages/{friend_username}")
@router.post("/chat/send/{friend_username}")
@router.post("/message/{friend_username}")
async def send_message(
    friend_username: str,
    data: MessageCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        return chat_service.send_message(db, current_user, friend_username, data.text, data.image_url)
    except chat_service.NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except chat_service.BadRequestError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/messages/{message_id}/read")
@router.post("/chat/messages/{message_id}/read")
def mark_messages_read(
    message_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        return chat_service.mark_messages_read(db, current_user, message_id)
    except chat_service.NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/messages/{message_id}")
@router.delete("/chat/messages/{message_id}")
def delete_message(
    message_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        return chat_service.delete_message(db, current_user, message_id)
    except chat_service.NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
