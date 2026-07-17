from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi import WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from datetime import datetime, timedelta, UTC
from fastapi import Query
import json
import shutil
import uuid
from database import engine
from models import User, Friend, Message
from sqlalchemy.orm import Session
from sqlalchemy import or_
from database import get_db

# Import configuration and security utilities
from backend.core.config import settings
from backend.core.security import (
    pwd_context,
    security,
    verify_password,
    create_access_token,
    get_current_user,
    verify_ws_token,
)


app = FastAPI()

# ✅ NEW: A simple set to track the IDs of everyone currently connected
online_users = {}

app.mount("/static", StaticFiles(directory=settings.STATIC_DIR), name="static")

app.mount("/uploads", StaticFiles(directory=settings.UPLOADS_DIR), name="uploads")

@app.get("/")
def frontend():
    return FileResponse("static/index.html")

User.metadata.create_all(bind=engine)


# ================= UTILS =================
def are_friends(db: Session, user_id: int, friend_id: int) -> bool:
    return db.query(Friend).filter(
        Friend.user_id == user_id,
        Friend.friend_id == friend_id,
        Friend.status == "accepted"
    ).first() is not None

def get_dm_room(user1, user2):
    return f"dm_{min(user1, user2)}_{max(user1, user2)}"

room_permissions = {}

def load_rooms_from_db():
    db = next(get_db())
    friendships = db.query(Friend).filter_by(status="accepted").all()

    for f in friendships:
        room = get_dm_room(f.user_id, f.friend_id)
        room_permissions[room] = [f.user_id, f.friend_id]

load_rooms_from_db()


class LoginRequest(BaseModel):
    username: str
    password: str

# ================= ROUTES =================
@app.post("/login")
def login(
    data: LoginRequest,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == data.username).first()

    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return {"access_token": token}

@app.post("/register")
def register(
    data: LoginRequest,
    db: Session = Depends(get_db)
):
    # 1. Check if username exists
    existing_user = db.query(User).filter(User.username == data.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")

    # 2. Create new user
    new_user = User(
        username=data.username,
        password_hash=pwd_context.hash(data.password),
        last_seen=datetime.now(UTC)
    )
    db.add(new_user)
    db.commit()

    return {"msg": "User created successfully"}

@app.get("/me")
def read_me(username: str = Depends(get_current_user)):
    return {"username": username}


# ================= WEBSOCKET CHAT =================

rooms = {}  # room_name -> list of (websocket, username)

def remove_connection_from_rooms(websocket: WebSocket):
    empty_rooms = []

    for room_id, members in rooms.items():
        rooms[room_id] = [
            (conn, member) for conn, member in members if conn != websocket
        ]
        if not rooms[room_id]:
            empty_rooms.append(room_id)

    for room_id in empty_rooms:
        del rooms[room_id]

@app.websocket("/ws")
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

            # print("Received:", data)

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
                        if member.id != user.id: # Don't send to self
                            await conn.send_text(json.dumps({
                                "type": "typing",
                                "sender": user.username
                            }))
                continue # Skip saving to DB

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

                if not are_friends(db, user.id, friend.id):
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
                ).order_by(Message.timestamp.asc()).limit(50).all()

                # Send past messages to THIS user only
                for msg in history:
                    sender_name = user.username if msg.sender_id == user.id else friend.username
                    await websocket.send_text(json.dumps({
                        "type": "chat",
                        "sender": sender_name,
                        "text": msg.content,
                        "image_url": msg.image_url
                    }))
                # ==========================================

                # await websocket.send_text(json.dumps({
                #     "type": "system",
                #     "message": f"Connected to secure channel with {friend.username}"
                # }))


            # ---------------- CHAT MESSAGE ----------------
            elif msg_type == "chat":
                friend_username = data.get("room") # Frontend says "alex"
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
            
            # ✅ NEW: Typing Handler
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

@app.get("/search")
def search_users(
    query: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Find users matching the query (partial match)
    users = db.query(User).filter(
        User.username.contains(query),
        User.username != current_user.username # Don't find yourself
    ).all()

    results = []
    for user in users:
        # Check friendship status
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

@app.post("/friends/request/{friend_username}")
def send_friend_request(
    friend_username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    friend = db.query(User).filter(User.username == friend_username).first()
    if not friend:
        raise HTTPException(status_code=404, detail="User not found")

    # 1. CHECK FOR EXISTING RELATIONSHIP (The Fix)
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


@app.get("/friends/requests")
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

@app.post("/friends/accept/{request_id}")
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

    # create reverse relationship
    reverse = Friend(
        user_id=current_user.id,
        friend_id=request.user_id,
        status="accepted"
    )

    db.add(reverse)
    db.commit()

    return {"msg": "Friend request accepted"}

# ... (Keep all existing code)

@app.get("/friends")
def get_friends_list(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
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
            # ✅ THE FIX: Check the global 'online_users' set
            is_active = friend_user.id in online_users

            results.append({
                "username": friend_user.username,
                # Send the timestamp to the frontend
                "last_seen": friend_user.last_seen,
                "is_online": is_active  # <--- Sending the Truth!
                })
    
    return results

@app.post("/upload")
async def upload_file(file: UploadFile = File(...), user: User = Depends(get_current_user)):
    file_ext = file.filename.split(".")[-1]
    filename = f"{uuid.uuid4()}.{file_ext}"
    file_path = f"{settings.UPLOADS_DIR}/{filename}"

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return {"url": f"/{settings.UPLOADS_DIR}/{filename}"}
