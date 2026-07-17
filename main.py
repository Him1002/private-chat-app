from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.db.database import engine
from backend.db.models import User

# Import configuration
from backend.core.config import settings


app = FastAPI()

app.mount("/static", StaticFiles(directory=settings.STATIC_DIR), name="static")

# Uploads static mount moved to backend/api/upload.py (register_uploads will mount it on the app)

@app.get("/")
def frontend():
    return FileResponse("static/index.html")

User.metadata.create_all(bind=engine)


# ================= ROUTES =================
from backend.api.auth import router as auth_router
from backend.api.chat import router as chat_router

app.include_router(auth_router)
app.include_router(chat_router)


# ================= WEBSOCKET CHAT =================

from backend.realtime.websocket import router as websocket_router

app.include_router(websocket_router)

from backend.api.friends import router as friends_router

app.include_router(friends_router)

from backend.api.upload import router as upload_router, register_uploads

app.include_router(upload_router)
# Mount the uploads static directory (preserves previous behavior)
register_uploads(app)
