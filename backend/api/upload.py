import mimetypes
import os

from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.security import get_current_user
from backend.db.database import get_db
from backend.db.models import User, Message

router = APIRouter()


@router.post("/upload")
async def upload_file(file: UploadFile = File(...), user: User = Depends(get_current_user)):
    """Thin controller: validate request and delegate upload business logic to the service layer.

    Preserves original behavior and response payload.
    """
    # Delegate to service that contains filename generation and storage logic
    from backend.services.upload_service import save_upload

    url = save_upload(file)
    return {"url": url}


@router.get("/uploads/{filename}")
async def get_uploaded_file(
    filename: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Serve private media assets with strict authentication and authorization checks.

    Authorization semantics:
    - Profile pictures: Accessible to all authenticated users.
    - Chat images: Accessible only to conversation participants (sender and receiver).
    - Deleted messages: Media immediately returns 404.
    - Unlinked media: Media not tied to an active profile picture or message returns 404.
    - Path traversal / invalid filenames: Safely rejected with 400.
    """
    # 1. Path traversal and filename safety validation
    if not filename or "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename")

    base_filename = os.path.basename(filename)
    uploads_dir = os.path.abspath(settings.UPLOADS_DIR)
    file_path = os.path.abspath(os.path.join(uploads_dir, base_filename))

    # Ensure resolved path is strictly within uploads_dir
    try:
        if os.path.commonpath([uploads_dir, file_path]) != uploads_dir:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename")
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename")

    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Media not found")

    # 2. Check if this file is a user's profile picture
    is_profile_pic = (
        db.query(User.id)
        .filter(User.profile_picture.like(f"%{base_filename}"))
        .first()
        is not None
    )

    if is_profile_pic:
        content_type, _ = mimetypes.guess_type(file_path)
        return FileResponse(
            file_path,
            media_type=content_type or "application/octet-stream",
            headers={"Cache-Control": "private, max-age=3600"},
        )

    # 3. Check if this file is associated with a chat message
    messages = (
        db.query(Message)
        .filter(Message.image_url.like(f"%{base_filename}"))
        .all()
    )

    if messages:
        # If all messages referencing this media are deleted, it is immediately inaccessible
        active_messages = [m for m in messages if not m.is_deleted]
        if not active_messages:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Media not found")

        # Only sender and receiver are authorized to access conversation media
        if not any(user.id in (m.sender_id, m.receiver_id) for m in active_messages):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this media")

        content_type, _ = mimetypes.guess_type(file_path)
        return FileResponse(
            file_path,
            media_type=content_type or "application/octet-stream",
            headers={"Cache-Control": "private, max-age=3600"},
        )

    # 4. Unlinked or unrecognized media files are rejected
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Media not found")


def register_uploads(app):
    """Legacy mount hook preserved for backward-compatibility with main.py.

    Public static file serving for /uploads is disabled in favor of the
    authenticated GET /uploads/{filename} endpoint on the upload router.
    """
    pass
