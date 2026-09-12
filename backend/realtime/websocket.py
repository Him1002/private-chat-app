from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Depends
from sqlalchemy.orm import Session
from datetime import datetime, UTC
import json
import logging

logger = logging.getLogger(__name__)

from backend.db.database import get_db
from backend.db.models import User, Friend, Message
from backend.core.security import verify_ws_token
from backend.services import chat_service
from backend.services import reaction_service

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
            try:
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise ValueError("Payload must be a JSON object")
            except (json.JSONDecodeError, ValueError):
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": "Invalid JSON payload",
                }))
                continue

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

                # Batch-load reactions for all history messages
                history_msg_ids = [m.id for m in history_messages]
                reactions_map = reaction_service.get_reactions_for_messages(db, history_msg_ids)

                for message in history_messages:
                    msg_reactions = reactions_map.get(message.id, [])
                    payload = chat_service.serialize_message_for_websocket(
                        message, user, friend, reactions=msg_reactions,
                    )
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
                reply_to_id = data.get("reply_to_message_id")

                try:
                    friend = chat_service.get_chat_friend(db, user, friend_username)
                except chat_service.NotFoundError:
                    continue

                room_id = get_dm_room(user.username, friend.username)

                # Parse reply_to_message_id if provided
                parsed_reply_to = None
                if reply_to_id is not None:
                    try:
                        parsed_reply_to = int(reply_to_id)
                    except (TypeError, ValueError):
                        await websocket.send_text(json.dumps({
                            "type": "error",
                            "message": "Invalid reply_to_message_id",
                        }))
                        continue

                try:
                    new_msg = chat_service.create_message(db, user, friend, text, img_url, reply_to_message_id=parsed_reply_to)
                except chat_service.BadRequestError as exc:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": str(exc),
                    }))
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

            # ---------------- DELETE MESSAGE ----------------
            elif msg_type == "message_delete":
                message_id = data.get("message_id")
                try:
                    message_id = int(message_id)
                except (TypeError, ValueError):
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Invalid message id",
                    }))
                    continue

                try:
                    chat_service.delete_message(db, user, message_id)
                except chat_service.NotFoundError as exc:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": str(exc),
                    }))
                    continue
                except chat_service.ForbiddenError as exc:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": str(exc),
                    }))
                    continue
                except chat_service.BadRequestError as exc:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": str(exc),
                    }))
                    continue

                deleted_message = db.query(chat_service.Message).filter(chat_service.Message.id == message_id).first()
                if not deleted_message:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Message not found",
                    }))
                    continue

                friend_id = deleted_message.receiver_id if deleted_message.sender_id == user.id else deleted_message.sender_id
                friend = db.query(User).filter(User.id == friend_id).first()
                if not friend:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "User not found",
                    }))
                    continue

                room_id = get_dm_room(user.username, friend.username)
                delete_payload = chat_service.serialize_message_for_websocket(
                    deleted_message,
                    user,
                    friend,
                    event_type="message_deleted",
                )

                if room_id in rooms:
                    for conn, target_user in rooms[room_id]:
                        await conn.send_text(json.dumps(delete_payload))
                else:
                    await websocket.send_text(json.dumps(delete_payload))

            # ---------------- EDIT MESSAGE ----------------
            elif msg_type == "message_edit":
                message_id = data.get("message_id")
                text = data.get("text")
                try:
                    message_id = int(message_id)
                except (TypeError, ValueError):
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Invalid message id",
                    }))
                    continue

                try:
                    updated_message = chat_service.edit_message(db, user, message_id, text)
                except chat_service.NotFoundError as exc:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": str(exc),
                    }))
                    continue
                except chat_service.ForbiddenError as exc:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": str(exc),
                    }))
                    continue
                except chat_service.BadRequestError as exc:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": str(exc),
                    }))
                    continue

                friend = db.query(User).filter(User.id == updated_message.receiver_id).first()
                if not friend:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "User not found",
                    }))
                    continue

                room_id = get_dm_room(user.username, friend.username)
                updated_payload = chat_service.serialize_message_for_websocket(
                    updated_message,
                    user,
                    friend,
                    event_type="message_updated",
                )

                sent_to_sender = False
                if room_id in rooms:
                    for conn, target_user in rooms[room_id]:
                        await conn.send_text(json.dumps(updated_payload))
                        if target_user.id == user.id:
                            sent_to_sender = True

                if not sent_to_sender:
                    await websocket.send_text(json.dumps(updated_payload))

            # ---------------- ADD REACTION ----------------
            elif msg_type == "reaction_add":
                message_id = data.get("message_id")
                emoji = data.get("emoji")
                try:
                    message_id = int(message_id)
                except (TypeError, ValueError):
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Invalid message id",
                    }))
                    continue

                try:
                    reactions = reaction_service.add_reaction(db, user, message_id, emoji)
                except reaction_service.NotFoundError as exc:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": str(exc),
                    }))
                    continue
                except reaction_service.BadRequestError as exc:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": str(exc),
                    }))
                    continue

                # Determine the DM room and broadcast the updated reactions
                reacted_msg = db.query(Message).filter(Message.id == message_id).first()
                if reacted_msg:
                    friend_id = reacted_msg.receiver_id if reacted_msg.sender_id == user.id else reacted_msg.sender_id
                    friend = db.query(User).filter(User.id == friend_id).first()
                    if friend:
                        room_id = get_dm_room(user.username, friend.username)
                        reaction_payload = {
                            "type": "reaction_update",
                            "message_id": message_id,
                            "reactions": reactions,
                        }
                        sent_to_sender = False
                        if room_id in rooms:
                            for conn, target_user in rooms[room_id]:
                                await conn.send_text(json.dumps(reaction_payload))
                                if target_user.id == user.id:
                                    sent_to_sender = True
                        if not sent_to_sender:
                            await websocket.send_text(json.dumps(reaction_payload))

            # ---------------- REMOVE REACTION ----------------
            elif msg_type == "reaction_remove":
                message_id = data.get("message_id")
                emoji = data.get("emoji")
                try:
                    message_id = int(message_id)
                except (TypeError, ValueError):
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Invalid message id",
                    }))
                    continue

                try:
                    reactions = reaction_service.remove_reaction(db, user, message_id, emoji)
                except reaction_service.NotFoundError as exc:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": str(exc),
                    }))
                    continue

                # Determine the DM room and broadcast the updated reactions
                reacted_msg = db.query(Message).filter(Message.id == message_id).first()
                if reacted_msg:
                    friend_id = reacted_msg.receiver_id if reacted_msg.sender_id == user.id else reacted_msg.sender_id
                    friend = db.query(User).filter(User.id == friend_id).first()
                    if friend:
                        room_id = get_dm_room(user.username, friend.username)
                        reaction_payload = {
                            "type": "reaction_update",
                            "message_id": message_id,
                            "reactions": reactions,
                        }
                        sent_to_sender = False
                        if room_id in rooms:
                            for conn, target_user in rooms[room_id]:
                                await conn.send_text(json.dumps(reaction_payload))
                                if target_user.id == user.id:
                                    sent_to_sender = True
                        if not sent_to_sender:
                            await websocket.send_text(json.dumps(reaction_payload))

    except WebSocketDisconnect:
        pass
    finally:
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
            try:
                db.commit()
            except Exception as exc:
                db.rollback()
                logger.error(f"Failed to update last_seen for user {user.username} on disconnect: {exc}")
            print(f"{user.username} disconnected (Offline)")
        else:
            print(f"{user.username} disconnected one tab ({online_users[user.id]} remaining)")
