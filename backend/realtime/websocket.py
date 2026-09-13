from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Depends
from sqlalchemy.orm import Session
from datetime import datetime, UTC
from typing import Optional
import json
import logging

logger = logging.getLogger(__name__)

from backend.db.database import get_db
from backend.db.models import User, Message
from backend.core.security import verify_ws_token
from backend.services import chat_service
from backend.services import reaction_service

router = APIRouter()

# ✅ NEW: A simple set to track the IDs of everyone currently connected
online_users = {}

rooms = {}  # room_name -> list of (websocket, username)


def get_dm_room(user1, user2):
    return f"dm_{min(user1, user2)}_{max(user1, user2)}"


def parse_integer_id(val) -> Optional[int]:
    """Validate and parse a positive integer ID, rejecting booleans, floats, negatives, and invalid types."""
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val if val > 0 else None
    if isinstance(val, str):
        val = val.strip()
        if val.isdigit():
            try:
                parsed = int(val)
                return parsed if parsed > 0 else None
            except ValueError:
                return None
    return None


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
                             token: Optional[str] = Query(None),
                             db: Session = Depends(get_db)
                             ):
    # Pre-accept token validation (SEC-07): Reject unauthenticated connections before accept
    if not token or not isinstance(token, str) or not token.strip():
        await websocket.close(code=1008)
        return

    try:
        user = verify_ws_token(token.strip(), db)
    except Exception as exc:
        logger.error("Unexpected error verifying WebSocket token: %s", exc, exc_info=True)
        await websocket.close(code=1011)
        return

    if not user:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    # ✅ CLOCK IN: Mark as globally online
    online_users[user.id] = online_users.get(user.id, 0) + 1
    logger.info("%s connected (Online)", user.username)

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
            if not isinstance(msg_type, str) or not msg_type.strip():
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": "Missing or invalid event type",
                }))
                continue

            # ✅ UPDATE ACTIVITY: Keep them "Fresh" in DB while chatting
            # (updates Last Seen timestamp without waiting for disconnect)
            user.last_seen = datetime.now(UTC)
            db.commit()

            # ---------------- TYPING SIGNAL (New) ----------------
            if msg_type == "typing":
                friend_username = data.get("room")
                if not isinstance(friend_username, str) or not friend_username.strip():
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Invalid room for typing event",
                    }))
                    continue

                # Calculate room ID to find the socket
                room_id = get_dm_room(user.username, friend_username.strip())

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
                if not isinstance(friend_username, str) or not friend_username.strip():
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Invalid room",
                    }))
                    continue

                friend_username = friend_username.strip()

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
                if not isinstance(friend_username, str) or not friend_username.strip():
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Invalid room",
                    }))
                    continue

                friend_username = friend_username.strip()
                text = data.get("text")
                if text is not None and not isinstance(text, str):
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Message text must be a string",
                    }))
                    continue

                img_url = data.get("image_url")
                if img_url is not None and not isinstance(img_url, str):
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Image URL must be a string",
                    }))
                    continue

                reply_to_id = data.get("reply_to_message_id")

                try:
                    friend = chat_service.get_chat_friend(db, user, friend_username)
                except chat_service.NotFoundError:
                    continue

                room_id = get_dm_room(user.username, friend.username)

                # Parse reply_to_message_id if provided
                parsed_reply_to = None
                if reply_to_id is not None:
                    parsed_reply_to = parse_integer_id(reply_to_id)
                    if parsed_reply_to is None:
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
                raw_message_id = data.get("message_id")
                message_id = parse_integer_id(raw_message_id)
                if message_id is None:
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
                raw_message_id = data.get("message_id")
                message_id = parse_integer_id(raw_message_id)
                if message_id is None:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Invalid message id",
                    }))
                    continue

                text = data.get("text")
                if text is not None and not isinstance(text, str):
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Message text must be a string",
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
                raw_message_id = data.get("message_id")
                message_id = parse_integer_id(raw_message_id)
                if message_id is None:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Invalid message id",
                    }))
                    continue

                emoji = data.get("emoji")
                if not isinstance(emoji, str) or not emoji.strip():
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Invalid emoji",
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
                raw_message_id = data.get("message_id")
                message_id = parse_integer_id(raw_message_id)
                if message_id is None:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Invalid message id",
                    }))
                    continue

                emoji = data.get("emoji")
                if not isinstance(emoji, str) or not emoji.strip():
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Invalid emoji",
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
    except Exception as exc:
        logger.error(
            "Unexpected error in WebSocket connection for user '%s': %s",
            getattr(user, "username", "unknown"),
            exc,
            exc_info=True,
        )
        # Attempt safe database rollback so transaction state is clean
        try:
            db.rollback()
        except Exception as db_exc:
            logger.debug("Failed to rollback DB session after WebSocket error: %s", db_exc)

        # Attempt to inform the client with generic error payload if socket is still open
        try:
            await websocket.send_text(json.dumps({
                "type": "error",
                "message": "An unexpected error occurred",
            }))
        except Exception:
            pass

        # Attempt defensive close with code 1011 (Internal Error)
        try:
            await websocket.close(code=1011)
        except Exception:
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
            logger.info("%s disconnected (Offline)", user.username)
        else:
            logger.info("%s disconnected one tab (%s remaining)", user.username, online_users[user.id])
