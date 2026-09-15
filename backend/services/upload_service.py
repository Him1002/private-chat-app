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
import os

from fastapi import UploadFile, HTTPException, status

from backend.core.config import settings

MAX_UPLOAD_SIZE = getattr(settings, "MAX_IMAGE_SIZE_BYTES", 10 * 1024 * 1024)
MAX_IMAGE_SIZE = getattr(settings, "MAX_IMAGE_SIZE_BYTES", 10 * 1024 * 1024)
MAX_VIDEO_SIZE = getattr(settings, "MAX_VIDEO_SIZE_BYTES", 50 * 1024 * 1024)

# Allowed magic bytes and their corresponding extensions
ALLOWED_MAGIC_BYTES = {
    b"\xFF\xD8\xFF": "jpeg",
    b"\x89PNG\r\n\x1a\n": "png",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"RIFF": "webp",
}

VIDEO_EXTENSIONS = {"mp4", "webm"}
IMAGE_EXTENSIONS = {"jpeg", "png", "gif", "webp"}


def is_video_file(filename_or_url: str) -> bool:
    """Return True if the given filename or URL has a supported video extension."""
    if not filename_or_url:
        return False
    ext = filename_or_url.lower().split("?")[0].split(".")[-1]
    return ext in VIDEO_EXTENSIONS


def get_file_size_limit(ext: str) -> int:
    """Return the configured size limit in bytes based on file extension."""
    if ext in VIDEO_EXTENSIONS:
        return getattr(settings, "MAX_VIDEO_SIZE_BYTES", 50 * 1024 * 1024)
    return getattr(settings, "MAX_IMAGE_SIZE_BYTES", 10 * 1024 * 1024)


def _file_ext_from_filename(original_filename: str) -> str:
    """Extract file extension using the original application's logic.

    Uses str.split('.')[-1] to preserve existing filename-generation behavior
    (including behavior when there is no dot in the original filename).
    """
    return original_filename.split(".")[-1]


def generate_filename(original_filename: str, validated_ext: str = None) -> str:
    """Generate a new filename based on a UUID and the original or validated extension.

    Preserves the exact formatting used by the previous implementation.
    If a validated extension is provided, it is used instead of trusting the original.
    """
    file_ext = validated_ext if validated_ext else _file_ext_from_filename(original_filename)
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


def get_file_ext_from_magic_bytes(header_bytes: bytes) -> str:
    """Determine the file extension by checking magic bytes against image and video allowlists."""
    # Check image types
    for magic, ext in ALLOWED_MAGIC_BYTES.items():
        if header_bytes.startswith(magic):
            # Extra check for WebP
            if ext == "webp" and (len(header_bytes) < 12 or header_bytes[8:12] != b"WEBP"):
                continue
            return ext

    # Check video types:
    # 1. MP4 / ISOBMFF: Box header has "ftyp" at byte offset 4..8
    if len(header_bytes) >= 8 and header_bytes[4:8] == b"ftyp":
        return "mp4"

    # 2. WebM: EBML header starts with 0x1A 0x45 0xDF 0xA3
    if header_bytes.startswith(b"\x1a\x45\xdf\xa3"):
        return "webm"

    raise HTTPException(
        status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        detail="Unsupported or invalid image file type"
    )


def save_upload(file: UploadFile) -> str:
    """Save UploadFile to the uploads directory and return its public URL.

    This function performs filename generation and file storage. It intentionally
    does NOT create the uploads directory to preserve existing behavior — any
    errors from missing directories will bubble up as before.

    Returns:
        The public URL (string) for the saved file, e.g. '/uploads/<filename>'.
    """
    # Read the first 32 bytes to determine file type from magic bytes
    header = file.file.read(32)
    if not header:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty file"
        )
    # This will raise HTTP 415 if unsupported
    validated_ext = get_file_ext_from_magic_bytes(header)
    # Generate filename using preserved logic but with validated extension
    filename = generate_filename(file.filename, validated_ext)
    file_path = upload_file_path(filename)
    max_size = get_file_size_limit(validated_ext)

    # Stream file contents to disk and enforce max size
    with open(file_path, "wb") as buffer:
        # Write the header first
        buffer.write(header)
        total_size = len(header)
        while True:
            chunk = file.file.read(64 * 1024)
            if not chunk:
                break
            total_size += len(chunk)
            if total_size > max_size:
                buffer.close()
                # Clean up the partial file
                try:
                    os.remove(file_path)
                except OSError:
                    pass
                raise HTTPException(
                    status_code=getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413),
                    detail="File too large"
                )
            buffer.write(chunk)

    return upload_url_for_filename(filename)
