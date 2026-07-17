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
from backend.db.database import engine
from backend.db.models import User, Friend, Message
from sqlalchemy.orm import Session
from sqlalchemy import or_
from backend.db.database import get_db

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

app.mount("/static", StaticFiles(directory=settings.STATIC_DIR), name="static")

app.mount("/uploads", StaticFiles(directory=settings.UPLOADS_DIR), name="uploads")

@app.get("/")
def frontend():
    return FileResponse("static/index.html")

User.metadata.create_all(bind=engine)


# ================= ROUTES =================
from backend.api.auth import router as auth_router

app.include_router(auth_router)


# ================= WEBSOCKET CHAT =================

from backend.realtime.websocket import router as websocket_router

app.include_router(websocket_router)

from backend.api.friends import router as friends_router

app.include_router(friends_router)

@app.post("/upload")
async def upload_file(file: UploadFile = File(...), user: User = Depends(get_current_user)):
    file_ext = file.filename.split(".")[-1]
    filename = f"{uuid.uuid4()}.{file_ext}"
    file_path = f"{settings.UPLOADS_DIR}/{filename}"

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return {"url": f"/{settings.UPLOADS_DIR}/{filename}"}
