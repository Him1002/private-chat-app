from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Depends
from sqlalchemy.orm import Session
from sqlalchemy import or_
from datetime import datetime, UTC
import json

from backend.db.database import get_db
from backend.db.models import User, Message, Friend
from backend.core.security import verify_ws_token

router = APIRouter()

# ✅ NEW: A simple set to track the IDs of everyone currently connected
online_users = {}

rooms = {}  # room_name -> list of (websocket, username)
room_permissions = {}


def get_dm_room(user1, user2):
    return f"dm_{min(user1, user2)}_{max(user1, user2)}"


def load_rooms_from_db():
    db = next(get_db())
    friendships = db.query(Friend).filter_by(status="accepted").all()

    for f in friendships:
        room = get_dm_room(f.user_id, f.friend_id)
        room_permissions[room] = [f.user_id, f.friend_id]


load_rooms_from_db()


def remove_connection_from_rooms(websocket: WebSocket):
    empty_rooms = []

    for room_id, members in list(rooms.items()):
        rooms[room_id] = [
            (conn, member) for conn, member in members if conn != websocket
        ]
        if not rooms[room_id]:
            empty_rooms.append(room_id)

    for room_id in empty_rooms:
        del rooms[room_id]


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket,
                             token: str = Query(...),
                             db: Session = Depends(get_db)
                             ):
    await websocket.accept()

    user = verify_ws_token(token, db)
    if not user:
        await websocket.close(code=1008)
        return

    # ✅ CLOCK IN: Mark as globally online
    online_users[user.id] = online_users.get(user.id, 0) + 1
    print(f"{user.username} connected (Online)")

    try:
        while True:
            raw = await websocket.receive_text()
            data = json.loads(raw)

            msg_type = data.get("type")

            # ✅ UPDATE ACTIVITY: Keep them "Fresh" in DB while chatting
            # (updates Last Seen timestamp without waiting for disconnect)
            user.last_seen = datetime.now(UTC)
            db.commit()

            # ---------------- TYPING SIGNAL (New) ----------------
            if msg_type == "typing":
                friend_username = data.get("room")
                # Calculate room ID to find the socket
                room_id = get_dm_room(user.username, friend_username)

                if room_id in rooms:
                    for conn, member in rooms[room_id]:
                        if member.id != user.id:  # Don't send to self
                            await conn.send_text(json.dumps({
                                "type": "typing",
                                "sender": user.username
                            }))
                continue  # Skip saving to DB

            # ---------------- JOIN ROOM ----------------
            if msg_type == "join":
                friend_username = data.get("room")

                friend = db.query(User).filter(User.username == friend_username).first()
                if not friend:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "User does not exist"
                    }))
                    continue

                # Reuse Friend model check for friendship
                is_friend = db.query(Friend).filter(
                    Friend.user_id == user.id,
                    Friend.friend_id == friend.id,
                    Friend.status == "accepted"
                ).first() is not None

                if not is_friend:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "You are not friends"
                    }))
                    continue

                room_id = get_dm_room(user.username, friend.username)

                remove_connection_from_rooms(websocket)

                if room_id not in rooms:
                    rooms[room_id] = []

                rooms[room_id].append((websocket, user))

                # 4. (Optional) Load History - We will add this in the NEXT step
                history = db.query(Message).filter(
                    or_(
                        (Message.sender_id == user.id) & (Message.receiver_id == friend.id),
                        (Message.sender_id == friend.id) & (Message.receiver_id == user.id)
                    )
                ).order_by(Message.timestamp.asc()).all()

                # Send past messages to THIS user only
                for msg in history:
                    sender_name = user.username if msg.sender_id == user.id else friend.username
                    await websocket.send_text(json.dumps({
                        "type": "chat",
                        "sender": sender_name,
                        "text": msg.content,
                        "image_url": msg.image_url
                    }))

            # ---------------- CHAT MESSAGE ----------------
            elif msg_type == "chat":
                friend_username = data.get("room")  # Frontend says "alex"
                text = data.get("text")
                img_url = data.get("image_url")

                # 1. Find the friend object again to get their ID
                friend = db.query(User).filter(User.username == friend_username).first()
                if not friend:
                    continue

                # 2. Calculate the Canonical Room ID again
                room_id = get_dm_room(user.username, friend.username)

                # 3. SAVE TO DATABASE (Persistence!)
                new_msg = Message(
                    sender_id=user.id,
                    receiver_id=friend.id,
                    content=text,
                    image_url=img_url,
                    timestamp=datetime.now(UTC)
                )
                db.add(new_msg)
                db.commit()

                # 4. Construct Payload
                message_payload = {
                    "type": "chat",
                    "sender": user.username,
                    "text": text,
                    "image_url": img_url,
                    "timestamp": new_msg.timestamp.isoformat()
                }

                # 5. Broadcast (Only if room exists in memory)
                if room_id in rooms:
                    for conn, target_user in rooms[room_id]:
                        # Optional: Check strict permissions again if you want
                        await conn.send_text(json.dumps(message_payload))

                else:
                    # Logic for when friend is OFFLINE:
                    # We already saved to DB, so just echo back to sender so they see their own msg
                    await websocket.send_text(json.dumps(message_payload))

    except WebSocketDisconnect:
        # ✅ CLOCK OUT: Remove from global online list
        connection_count = online_users.get(user.id, 0)
        if connection_count <= 1:
            online_users.pop(user.id, None)
        else:
            online_users[user.id] = connection_count - 1

        remove_connection_from_rooms(websocket)

        # 2. ✅ Update Last Seen in DB
        if connection_count <= 1:
            user.last_seen = datetime.now(UTC)
            db.commit()
            print(f"{user.username} disconnected (Offline)")
        else:
            print(f"{user.username} disconnected one tab ({online_users[user.id]} remaining)")
