from fastapi import APIRouter, UploadFile, File, Depends
from fastapi.staticfiles import StaticFiles

import shutil
import uuid

from backend.core.config import settings
from backend.core.security import get_current_user
from backend.db.models import User

router = APIRouter()


@router.post("/upload")
async def upload_file(file: UploadFile = File(...), user: User = Depends(get_current_user)):
    """Handle file uploads and return a URL to the saved file.

    Behavior preserved from main.py: filename generation, path, and response format.
    This function intentionally does not create the uploads directory to preserve
    existing application behavior.
    """
    file_ext = file.filename.split(".")[-1]
    filename = f"{uuid.uuid4()}.{file_ext}"
    file_path = f"{settings.UPLOADS_DIR}/{filename}"

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return {"url": f"/{settings.UPLOADS_DIR}/{filename}"}


def register_uploads(app):
    """Mount the uploads static directory on the FastAPI app.

    Separated into a function so the main application can call it after
    importing this module. This preserves the original app.mount call
    that lived in main.py.
    """
    app.mount("/uploads", StaticFiles(directory=settings.UPLOADS_DIR), name="uploads")
