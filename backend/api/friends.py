from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from sqlalchemy import or_
from importlib import import_module
from backend.services.friend_service import are_friends
from backend.db.database import get_db
from backend.db.models import User, Friend
from backend.core.security import get_current_user

router = APIRouter()

@router.get("/search")
def search_users(
    query: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
#   # Delay importing main to avoid circular imports
#     main = import_module("main")
#     are_friends = main.are_friend  s

    users = db.query(User).filter(
        User.username.contains(query),
        User.username != current_user.username
    ).all()

    results = []
    for user in users:
        is_friend = are_friends(db, current_user.id, user.id)

        pending = db.query(Friend).filter(
            Friend.user_id == current_user.id,
            Friend.friend_id == user.id,
            Friend.status == "pending"
        ).first()

        status = "friend" if is_friend else "pending" if pending else "none"

        results.append({
            "username": user.username,
            "status": status
        })

    return results


@router.post("/friends/request/{friend_username}")
def send_friend_request(
    friend_username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    friend = db.query(User).filter(User.username == friend_username).first()
    if not friend:
        raise HTTPException(status_code=404, detail="User not found")

    existing = db.query(Friend).filter(
        or_(
            (Friend.user_id == current_user.id) & (Friend.friend_id == friend.id),
            (Friend.user_id == friend.id) & (Friend.friend_id == current_user.id)
        )
    ).first()

    if existing:
        if existing.status == "accepted":
            return {"msg": "You are already friends"}
        else:
            return {"msg": "Request already pending"}

    request = Friend(
        user_id=current_user.id,
        friend_id=friend.id
    )
    db.add(request)
    db.commit()

    return {"msg": "Friend request sent"}


@router.get("/friends/requests")
def get_friend_requests(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    requests = db.query(Friend).filter(
        Friend.friend_id == current_user.id,
        Friend.status == "pending"
    ).all()

    results = []
    for r in requests:
        sender = db.query(User).filter(User.id == r.user_id).first()
        if sender:
            results.append({
                "request_id": r.id,
                "username": sender.username
            })
    return results


@router.post("/friends/accept/{request_id}")
def accept_friend_request(
    request_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    request = db.query(Friend).filter(
        Friend.id == request_id,
        Friend.friend_id == current_user.id,
        Friend.status == "pending"
    ).first()

    if not request:
        raise HTTPException(status_code=404, detail="Request not found")

    request.status = "accepted"

    reverse = Friend(
        user_id=current_user.id,
        friend_id=request.user_id,
        status="accepted"
    )

    db.add(reverse)
    db.commit()

    return {"msg": "Friend request accepted"}


@router.get("/friends")
def get_friends_list(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ws_mod = import_module("backend.realtime.websocket")
    online_users = ws_mod.online_users
    # Get all accepted friendships
    friendships = db.query(Friend).filter(
        Friend.user_id == current_user.id,
        Friend.status == "accepted"
    ).all()

    results = []
    for f in friendships:
        fid = f.friend_id if f.user_id == current_user.id else f.user_id
        friend_user = db.query(User).filter(User.id == fid).first()
        if friend_user:
            is_active = friend_user.id in online_users

            results.append({
                "username": friend_user.username,
                "last_seen": friend_user.last_seen,
                "is_online": is_active
            })

    return results
