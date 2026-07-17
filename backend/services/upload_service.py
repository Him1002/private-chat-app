"""Upload service containing business logic for handling file uploads.

This module centralizes upload-related logic such as filename generation,
path generation, and storing files to disk. It intentionally preserves the
original behavior of not creating the uploads directory (so callers must ensure
it exists or handle errors the same way the original code did).

Do NOT import FastAPI application objects or depend on request/response
internals here. UploadFile is accepted as an argument for convenience.
"""
from typing import Tuple
import shutil
import uuid

from fastapi import UploadFile

from backend.core.config import settings


def _file_ext_from_filename(original_filename: str) -> str:
    """Extract file extension using the original application's logic.

    Uses str.split('.')[-1] to preserve existing filename-generation behavior
    (including behavior when there is no dot in the original filename).
    """
    return original_filename.split(".")[-1]


def generate_filename(original_filename: str) -> str:
    """Generate a new filename based on a UUID and the original extension.

    Preserves the exact formatting used by the previous implementation.
    """
    file_ext = _file_ext_from_filename(original_filename)
    return f"{uuid.uuid4()}.{file_ext}"


def upload_file_path(filename: str) -> str:
    """Return the filesystem path where the given filename should be stored.

    Maintains the same UPLOADS_DIR/filename string format used by the app so
    that behavior and returned URLs remain unchanged.
    """
    return f"{settings.UPLOADS_DIR}/{filename}"


def upload_url_for_filename(filename: str) -> str:
    """Return the public URL path for a stored filename.

    The application expects returned URLs to look like '/uploads/<filename>'.
    """
    return f"/{settings.UPLOADS_DIR}/{filename}"


def save_upload(file: UploadFile) -> str:
    """Save UploadFile to the uploads directory and return its public URL.

    This function performs filename generation and file storage. It intentionally
    does NOT create the uploads directory to preserve existing behavior — any
    errors from missing directories will bubble up as before.

    Returns:
        The public URL (string) for the saved file, e.g. '/uploads/<filename>'.
    """
    # Generate filename using preserved logic
    filename = generate_filename(file.filename)
    file_path = upload_file_path(filename)

    # Stream file contents to disk (preserves original implementation)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return upload_url_for_filename(filename)
