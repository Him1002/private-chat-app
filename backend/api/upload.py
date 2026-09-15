import mimetypes
import os
import re
from typing import Optional
from urllib.parse import quote

from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Query, status
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

    Preserves original behavior and response payload while adding file metadata.
    """
    from backend.services.upload_service import save_upload

    result = save_upload(file)
    if isinstance(result, dict):
        return {"url": result["url"]}
    return {"url": result}


@router.get("/uploads/{filename}")
async def get_uploaded_file(
    filename: str,
    download: Optional[int] = Query(None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Serve private media assets with strict authentication and authorization checks.

    Authorization semantics:
    - Profile pictures: Accessible to all authenticated users.
    - Chat media: Accessible only to conversation participants (sender and receiver).
    - Deleted messages: Media immediately returns 404.
    - Unlinked media: Media not tied to an active profile picture or message returns 404.
    - Path traversal / invalid filenames: Safely rejected with 400.
    """
    # 1. Path traversal and filename safety validation
    if not filename or "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename")

    base_filename = os.path.basename(filename)
    # Sidecar metadata files are strictly internal and cannot be directly requested
    if base_filename.endswith(".meta.json"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Media not found")

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
            headers={
                "Cache-Control": "private, max-age=3600",
                "X-Content-Type-Options": "nosniff",
            },
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

        from backend.services.upload_service import (
            get_upload_metadata,
            DOWNLOAD_ONLY_EXTENSIONS,
        )

        ext = base_filename.lower().split(".")[-1]

        # Resolve trusted original filename from metadata or message content
        meta = get_upload_metadata(base_filename)
        original_name = None
        if meta and meta.get("original_filename"):
            original_name = meta["original_filename"]
        elif active_messages and active_messages[0].content:
            original_name = active_messages[0].content
        else:
            original_name = base_filename

        # Sanitize filename for headers (prevent header injection)
        safe_ascii = re.sub(r'[^a-zA-Z0-9._-]', '_', original_name)
        rfc5987_val = quote(original_name.encode("utf-8"))

        headers = {
            "Cache-Control": "private, max-age=3600",
            "X-Content-Type-Options": "nosniff",
        }

        # Determine disposition: attachment for ?download=1 or download-only formats
        is_download = (download == 1) or (ext in DOWNLOAD_ONLY_EXTENSIONS)
        if is_download:
            headers["Content-Disposition"] = f'attachment; filename="{safe_ascii}"; filename*=UTF-8\'\'{rfc5987_val}'
        elif ext in {"pdf", "txt", "json"}:
            headers["Content-Disposition"] = f'inline; filename="{safe_ascii}"; filename*=UTF-8\'\'{rfc5987_val}'

        # Canonical Content-Type resolution
        if ext == "pdf":
            content_type = "application/pdf"
        elif ext == "txt":
            content_type = "text/plain; charset=utf-8"
        elif ext == "csv":
            content_type = "text/csv; charset=utf-8"
        elif ext == "json":
            content_type = "application/json"
        elif ext == "docx":
            content_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        elif ext == "xlsx":
            content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        elif ext == "pptx":
            content_type = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        elif ext == "mp4":
            content_type = "video/mp4"
        elif ext == "webm":
            content_type = "video/webm"
        else:
            content_type, _ = mimetypes.guess_type(file_path)

        return FileResponse(
            file_path,
            media_type=content_type or "application/octet-stream",
            headers=headers,
        )

    # 4. Unlinked or unrecognized media files are rejected
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Media not found")


def register_uploads(app):
    """Legacy mount hook preserved for backward-compatibility with main.py.

    Public static file serving for /uploads is disabled in favor of the
    authenticated GET /uploads/{filename} endpoint on the upload router.
    """
    pass
