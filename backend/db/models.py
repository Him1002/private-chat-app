from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean
from backend.db.database import Base
from sqlalchemy.orm import relationship
from datetime import datetime, UTC

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    last_seen = Column(DateTime, default=datetime.now(UTC))

class Friend(Base):
    __tablename__ = "friends"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    friend_id = Column(Integer, ForeignKey("users.id"))
    status = Column(String, default="pending")

# ✅ NEW: Table to store chat history
class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    receiver_id = Column(Integer, ForeignKey("users.id"))
    content = Column(String)
    image_url = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.now(UTC))

    # Message state for future features (backwards compatible defaults/nullable)
    is_read = Column(Boolean, default=False, nullable=False)
    read_at = Column(DateTime, nullable=True)

    edited_at = Column(DateTime, nullable=True)

    is_deleted = Column(Boolean, default=False, nullable=False)
    deleted_at = Column(DateTime, nullable=True)

    # Self-referencing optional FK for replies; nullable and doesn't affect existing rows
    reply_to_message_id = Column(Integer, ForeignKey("messages.id"), nullable=True)

    # ORM relationship to access the parent message and replies collection.
    # remote_side ensures SQLAlchemy understands this is a self-referential relationship.
    reply_to = relationship("Message", remote_side=[id], backref="replies", uselist=False)
