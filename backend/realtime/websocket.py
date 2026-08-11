from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Depends
from sqlalchemy.orm import Session
from datetime import datetime, UTC
import json

from backend.db.database import get_db
from backend.db.models import User, Friend
from backend.core.security import verify_ws_token
from backend.services import chat_service

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

                try:
                    friend = chat_service.get_chat_friend(db, user, friend_username)
                except chat_service.NotFoundError as exc:
                    message = "User does not exist" if str(exc) == "User not found" else "You are not friends"
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": message
                    }))
                    continue

                room_id = get_dm_room(user.username, friend.username)

                remove_connection_from_rooms(websocket)

                if room_id not in rooms:
                    rooms[room_id] = []

                rooms[room_id].append((websocket, user))

                _, history_messages = chat_service.get_chat_messages(db, user, friend_username)

                for message in history_messages:
                    payload = chat_service.serialize_message_for_websocket(message, user, friend)
                    await websocket.send_text(json.dumps(payload))

                newly_read_messages = chat_service.mark_conversation_messages_read(db, user, friend)
                if newly_read_messages:
                    message_ids = [message.id for message in newly_read_messages]
                    read_at = newly_read_messages[0].read_at
                    read_payload = {
                        "type": "messages_read",
                        "message_ids": message_ids,
                        "read_at": read_at.isoformat().replace("+00:00", "Z") if read_at else None,
                        "reader": user.username,
                    }
                    if room_id in rooms:
                        for conn, target_user in rooms[room_id]:
                            if target_user.id == friend.id:
                                await conn.send_text(json.dumps(read_payload))

            # ---------------- CHAT MESSAGE ----------------
            elif msg_type == "chat":
                friend_username = data.get("room")  # Frontend says "alex"
                text = data.get("text")
                img_url = data.get("image_url")

                try:
                    friend = chat_service.get_chat_friend(db, user, friend_username)
                except chat_service.NotFoundError:
                    continue

                room_id = get_dm_room(user.username, friend.username)

                try:
                    new_msg = chat_service.create_message(db, user, friend, text, img_url)
                except chat_service.BadRequestError:
                    continue

                message_payload = chat_service.serialize_message_for_websocket(new_msg, user, friend)

                sender_received = False
                recipient_received = False
                if room_id in rooms:
                    for conn, target_user in rooms[room_id]:
                        await conn.send_text(json.dumps(message_payload))
                        if target_user.id == user.id:
                            sender_received = True
                        if target_user.id == friend.id:
                            recipient_received = True

                    if recipient_received:
                        delivered_payload = {
                            "type": "message_status",
                            "message_id": new_msg.id,
                            "status": "delivered",
                        }
                        for conn, target_user in rooms[room_id]:
                            if target_user.id == user.id:
                                await conn.send_text(json.dumps(delivered_payload))

                else:
                    await websocket.send_text(json.dumps(message_payload))
                    sender_received = True

                if not sender_received:
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
