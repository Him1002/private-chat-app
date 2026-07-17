from sqlalchemy.orm import Session
from sqlalchemy import or_
from backend.db.models import User, Friend
from typing import List, Dict, Optional


def are_friends(db: Session, user_id: int, other_id: int) -> bool:
    """Return True if there is an accepted friendship between user_id and other_id.
    Checks both directions for safety.
    """
    f = db.query(Friend).filter(
        or_(
            (Friend.user_id == user_id) & (Friend.friend_id == other_id),
            (Friend.user_id == other_id) & (Friend.friend_id == user_id),
        ),
        Friend.status == "accepted"
    ).first()

    return bool(f)


def search_users(db: Session, query: str, current_user_id: int) -> List[Dict]:
    """Search users by username and return list with friendship status (friend/pending/none).
    This function contains pure business logic and does not raise HTTP exceptions.
    """
    users = db.query(User).filter(
        User.username.contains(query),
        User.id != current_user_id
    ).all()

    results = []
    for user in users:
        is_friend = are_friends(db, current_user_id, user.id)

        pending = db.query(Friend).filter(
            Friend.user_id == current_user_id,
            Friend.friend_id == user.id,
            Friend.status == "pending"
        ).first()

        status = "friend" if is_friend else "pending" if pending else "none"

        results.append({
            "username": user.username,
            "status": status
        })

    return results


def create_friend_request(db: Session, current_user_id: int, friend_username: str) -> Dict:
    """Create a friend request from current_user_id to the user with friend_username.
    Returns a dict with a message on success. Raises ValueError if the target user doesn't exist
    or the request/relationship already exists.
    """
    friend = db.query(User).filter(User.username == friend_username).first()
    if not friend:
        raise ValueError("User not found")

    # Check for existing relationship or request in either direction
    existing = db.query(Friend).filter(
        or_(
            (Friend.user_id == current_user_id) & (Friend.friend_id == friend.id),
            (Friend.user_id == friend.id) & (Friend.friend_id == current_user_id)
        )
    ).first()

    if existing:
        if existing.status == "accepted":
            return {"msg": "You are already friends"}
        else:
            return {"msg": "Request already pending"}

    request = Friend(
        user_id=current_user_id,
        friend_id=friend.id
    )
    db.add(request)
    db.commit()

    return {"msg": "Friend request sent"}


def get_pending_requests(db: Session, current_user_id: int) -> List[Dict]:
    """Return pending friend requests received by current_user_id as a list of dicts
    with request_id and username.
    """
    requests = db.query(Friend).filter(
        Friend.friend_id == current_user_id,
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


def accept_friend_request(db: Session, request_id: int, current_user_id: int) -> Dict:
    """Accept a friend request identified by request_id for current_user_id.
    Returns a dict with a message on success. Raises ValueError if request not found.
    """
    request = db.query(Friend).filter(
        Friend.id == request_id,
        Friend.friend_id == current_user_id,
        Friend.status == "pending"
    ).first()

    if not request:
        raise ValueError("Request not found")

    request.status = "accepted"

    reverse = Friend(
        user_id=current_user_id,
        friend_id=request.user_id,
        status="accepted"
    )

    db.add(reverse)
    db.commit()

    return {"msg": "Friend request accepted"}


def get_friends_list(db: Session, current_user_id: int, online_users: Optional[set] = None) -> List[Dict]:
    """Retrieve the current user's friends list. If online_users set is provided, mark which friends
    are online. Returns list of dicts with username, last_seen and is_online.
    """
    # Get all accepted friendships where the current_user is the owner of the row
    friendships = db.query(Friend).filter(
        Friend.user_id == current_user_id,
        Friend.status == "accepted"
    ).all()

    results = []
    for f in friendships:
        fid = f.friend_id if f.user_id == current_user_id else f.user_id
        friend_user = db.query(User).filter(User.id == fid).first()
        if friend_user:
            is_active = False
            if online_users is not None:
                is_active = friend_user.id in online_users

            results.append({
                "username": friend_user.username,
                "last_seen": friend_user.last_seen,
                "is_online": is_active
            })

    return results
