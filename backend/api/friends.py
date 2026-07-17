from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from importlib import import_module
from backend.services.friend_service import (
    are_friends,
    search_users as service_search_users,
    create_friend_request as service_create_friend_request,
    get_pending_requests as service_get_pending_requests,
    accept_friend_request as service_accept_friend_request,
    get_friends_list as service_get_friends_list,
)
from backend.db.database import get_db
from backend.db.models import User
from backend.core.security import get_current_user

router = APIRouter()

@router.get("/search")
def search_users(
    query: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Delegate business logic to the service layer
    results = service_search_users(db=db, query=query, current_user_id=current_user.id)
    return results


@router.post("/friends/request/{friend_username}")
def send_friend_request(
    friend_username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        result = service_create_friend_request(db=db, current_user_id=current_user.id, friend_username=friend_username)
        return result
    except ValueError as e:
        # Translate service errors to HTTP responses where appropriate
        if str(e) == "User not found":
            raise HTTPException(status_code=404, detail=str(e))
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/friends/requests")
def get_friend_requests(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    results = service_get_pending_requests(db=db, current_user_id=current_user.id)
    return results


@router.post("/friends/accept/{request_id}")
def accept_friend_request(
    request_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        result = service_accept_friend_request(db=db, request_id=request_id, current_user_id=current_user.id)
        return result
    except ValueError as e:
        if str(e) == "Request not found":
            raise HTTPException(status_code=404, detail=str(e))
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/friends")
def get_friends_list(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Keep online-users retrieval HTTP-specific (depends on runtime module)
    ws_mod = import_module("backend.realtime.websocket")
    online_users = ws_mod.online_users

    results = service_get_friends_list(db=db, current_user_id=current_user.id, online_users=online_users)
    return results
