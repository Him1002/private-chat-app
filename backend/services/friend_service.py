from sqlalchemy.orm import Session
from backend.db.models import Friend

def are_friends(db: Session, user_id: int, friend_id: int) -> bool:
    return db.query(Friend).filter(
        Friend.user_id == user_id,
        Friend.friend_id == friend_id,
        Friend.status == "accepted"
    ).first() is not None