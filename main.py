import mimetypes
import os

# Ensure standard MIME types across all OS platforms (fixes Windows registry mapping of .js to text/plain)
mimetypes.init()
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("application/javascript", ".mjs")

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware


# Import configuration, logging, and security middleware
from backend.core.config import settings
from backend.core.security import SecurityHeadersMiddleware
from backend.core.logging_config import setup_logging
from backend.core.error_handlers import register_exception_handlers

# Initialize standard-library logging configuration early
setup_logging()

app = FastAPI()

# Register centralized exception handlers (S5-T07)
register_exception_handlers(app)

# ================= SECURITY MIDDLEWARE =================
# Configurable CORS (S5-T05)
allow_origins = settings.ALLOWED_ORIGINS
allow_credentials = bool(allow_origins and "*" not in allow_origins)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# HTTP Security Headers (S5-T05)
app.add_middleware(SecurityHeadersMiddleware)

app.mount("/static", StaticFiles(directory=settings.STATIC_DIR), name="static")

# Uploads static mount moved to backend/api/upload.py (register_uploads will mount it on the app)

@app.get("/")
def frontend():
    return FileResponse(os.path.join(settings.STATIC_DIR, "index.html"))



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

from backend.api.profile import router as profile_router
app.include_router(profile_router)
