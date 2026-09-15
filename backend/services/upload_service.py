"""Upload service containing business logic for handling file uploads.

This module centralizes upload-related logic such as filename generation,
path generation, content validation, and storing files to disk. It intentionally
preserves the original behavior of not creating the uploads directory (so callers
must ensure it exists or handle errors the same way the original code did).

Do NOT import FastAPI application objects or depend on request/response
internals here. UploadFile is accepted as an argument for convenience.
"""
from typing import Optional, Dict, Union
from datetime import datetime, timezone
import json
import mimetypes
import os
import re
import shutil
import uuid
import zipfile

from fastapi import UploadFile, HTTPException, status

from backend.core.config import settings

MAX_UPLOAD_SIZE = getattr(settings, "MAX_IMAGE_SIZE_BYTES", 10 * 1024 * 1024)
MAX_IMAGE_SIZE = getattr(settings, "MAX_IMAGE_SIZE_BYTES", 10 * 1024 * 1024)
MAX_VIDEO_SIZE = getattr(settings, "MAX_VIDEO_SIZE_BYTES", 50 * 1024 * 1024)
MAX_FILE_SIZE = getattr(settings, "MAX_FILE_SIZE_BYTES", 25 * 1024 * 1024)

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
DOCUMENT_EXTENSIONS = {"pdf", "txt", "csv", "json", "docx", "xlsx", "pptx"}
DOWNLOAD_ONLY_EXTENSIONS = {"docx", "xlsx", "pptx", "csv"}
ALL_ALLOWED_EXTENSIONS = IMAGE_EXTENSIONS | VIDEO_EXTENSIONS | DOCUMENT_EXTENSIONS

# Common dangerous binary and executable signatures to reject immediately
DANGEROUS_MAGIC_PREFIXES = [
    b"MZ",                # DOS/PE executable (.exe, .dll)
    b"\x7fELF",           # Linux ELF executable
    b"\xca\xfe\xba\xbe",  # Java class / Mach-O universal binary
    b"<!DOCTYPE",        # HTML markup
    b"<doctype",         # HTML markup (case-insensitive check handled below)
    b"<html",             # HTML tag
    b"<HTML",             # HTML tag
    b"<?xml",             # XML / SVG
    b"<svg",              # SVG vector image
    b"<SVG",              # SVG vector image
    b"#!",                # Shebang script
]


def is_video_file(filename_or_url: str) -> bool:
    """Return True if the given filename or URL has a supported video extension."""
    if not filename_or_url:
        return False
    ext = filename_or_url.lower().split("?")[0].split(".")[-1]
    return ext in VIDEO_EXTENSIONS


def is_document_file(filename_or_url: str) -> bool:
    """Return True if the given filename or URL has a supported document extension."""
    if not filename_or_url:
        return False
    ext = filename_or_url.lower().split("?")[0].split(".")[-1]
    return ext in DOCUMENT_EXTENSIONS


def get_file_size_limit(ext: str) -> int:
    """Return the configured size limit in bytes based on file extension."""
    if ext in VIDEO_EXTENSIONS:
        return getattr(settings, "MAX_VIDEO_SIZE_BYTES", 50 * 1024 * 1024)
    if ext in DOCUMENT_EXTENSIONS:
        return getattr(settings, "MAX_FILE_SIZE_BYTES", 25 * 1024 * 1024)
    return getattr(settings, "MAX_IMAGE_SIZE_BYTES", 10 * 1024 * 1024)


def _file_ext_from_filename(original_filename: str) -> str:
    """Extract file extension using the original application's logic.

    Uses str.split('.')[-1] to preserve existing filename-generation behavior
    (including behavior when there is no dot in the original filename).
    """
    if not original_filename or "." not in original_filename:
        return ""
    return original_filename.split(".")[-1]


def sanitize_original_filename(filename: str, ext: str) -> str:
    """Sanitize client-provided filename to prevent path traversal, control chars, and header injection."""
    if not filename:
        return f"file.{ext}"
    # Strip any directory components
    base = os.path.basename(filename.replace("\\", "/"))
    # Remove control characters, newlines, carriage returns, double quotes, and semicolons
    cleaned = re.sub(r'[\r\n\t\x00";]', '', base).strip()
    # Strip dangerous shell/path characters
    cleaned = re.sub(r'[<>{}\[\]|\\^~`]', '', cleaned)
    if not cleaned or cleaned in (".", ".."):
        return f"file.{ext}"
    # Ensure it ends with .ext if not already
    if not cleaned.lower().endswith(f".{ext.lower()}"):
        cleaned = f"{cleaned}.{ext}"
    return cleaned


def generate_filename(original_filename: str, validated_ext: str = None) -> str:
    """Generate a new filename based on a UUID and the original or validated extension.

    Preserves the exact formatting used by the previous implementation.
    If a validated extension is provided, it is used instead of trusting the original.
    """
    file_ext = validated_ext if validated_ext else _file_ext_from_filename(original_filename)
    return f"{uuid.uuid4()}.{file_ext}"


def upload_file_path(filename: str) -> str:
    """Return the filesystem path where the given filename should be stored."""
    return f"{settings.UPLOADS_DIR}/{filename}"


def upload_url_for_filename(filename: str) -> str:
    """Return the public URL path for a stored filename."""
    return f"/{settings.UPLOADS_DIR}/{filename}"


def get_metadata_path_for_file(filename_or_url: str) -> str:
    """Return the filesystem path for the sidecar metadata JSON file."""
    base = os.path.basename(filename_or_url.split("?")[0])
    uuid_part = base.rsplit(".", 1)[0]
    return os.path.join(settings.UPLOADS_DIR, f"{uuid_part}.meta.json")


def get_upload_metadata(filename_or_url: str) -> Optional[dict]:
    """Retrieve trusted upload metadata saved during file upload."""
    if not filename_or_url:
        return None
    meta_path = get_metadata_path_for_file(filename_or_url)
    if os.path.exists(meta_path) and os.path.isfile(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def validate_ooxml_structure(file_path: str, ext: str) -> None:
    """Validate OOXML package structure using Python's built-in zipfile without extraction.

    Requirements:
    - Must be a valid zip archive.
    - Must contain [Content_Types].xml.
    - Expected package structure:
      - docx: contains 'word/' (e.g. 'word/document.xml')
      - xlsx: contains 'xl/' (e.g. 'xl/workbook.xml')
      - pptx: contains 'ppt/' (e.g. 'ppt/presentation.xml')
    """
    if not zipfile.is_zipfile(file_path):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Invalid or corrupted Office Open XML document",
        )

    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            names = [name.lower() for name in zf.namelist()]
            if "[content_types].xml" not in names:
                raise HTTPException(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    detail="Office Open XML document missing [Content_Types].xml",
                )
            if ext == "docx" and not any(n.startswith("word/") for n in names):
                raise HTTPException(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    detail="Invalid Word document package structure",
                )
            if ext == "xlsx" and not any(n.startswith("xl/") for n in names):
                raise HTTPException(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    detail="Invalid Excel document package structure",
                )
            if ext == "pptx" and not any(n.startswith("ppt/") for n in names):
                raise HTTPException(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    detail="Invalid PowerPoint document package structure",
                )
    except zipfile.BadZipFile:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Corrupted Office Open XML document",
        )


def validate_json_content(file_path: str) -> None:
    """Validate that the complete file content is valid UTF-8 JSON."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if b"\x00" in data:
            raise ValueError("Null bytes not permitted in JSON document")
        text = data.decode("utf-8")
        json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Invalid or malformed JSON file",
        )


def validate_text_content(file_path: str, ext: str) -> None:
    """Validate that plain text or CSV file contains valid UTF-8 and no null bytes."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if b"\x00" in data:
            raise ValueError("Binary null bytes not permitted in text document")
        data.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Invalid or malformed {ext.upper()} file encoding",
        )


def get_file_ext_from_magic_bytes(header_bytes: bytes, original_filename: str = "") -> str:
    """Determine the file extension by checking magic bytes against allowlists.

    Preserves exact detection behavior for images and videos, and validates
    allowed document extensions (PDF, DOCX, XLSX, PPTX, TXT, CSV, JSON).
    """
    orig_ext = _file_ext_from_filename(original_filename).lower() if original_filename else ""

    # If filename indicates an image, strictly validate against image magic bytes
    if orig_ext in {"jpg", "jpeg", "png", "gif", "webp"}:
        for magic, ext in ALLOWED_MAGIC_BYTES.items():
            if header_bytes.startswith(magic):
                if ext == "webp" and (len(header_bytes) < 12 or header_bytes[8:12] != b"WEBP"):
                    continue
                return ext
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported or invalid image file type",
        )

    # If filename indicates a video, strictly validate against video magic bytes
    if orig_ext in {"mp4", "webm"}:
        if len(header_bytes) >= 8 and header_bytes[4:8] == b"ftyp":
            return "mp4"
        if header_bytes.startswith(b"\x1a\x45\xdf\xa3"):
            return "webm"
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported or invalid image file type",
        )

    # Check image types (when extension not explicitly image)
    for magic, ext in ALLOWED_MAGIC_BYTES.items():
        if header_bytes.startswith(magic):
            if ext == "webp" and (len(header_bytes) < 12 or header_bytes[8:12] != b"WEBP"):
                continue
            return ext

    # Check video types (when extension not explicitly video)
    if len(header_bytes) >= 8 and header_bytes[4:8] == b"ftyp":
        return "mp4"
    if header_bytes.startswith(b"\x1a\x45\xdf\xa3"):
        return "webm"

    # Check document types with original filename context
    if orig_ext:
        if orig_ext == "pdf":
            if header_bytes.startswith(b"%PDF-"):
                return "pdf"
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="Unsupported or invalid image file type",
            )

        if orig_ext in {"docx", "xlsx", "pptx"}:
            if header_bytes.startswith(b"PK\x03\x04"):
                return orig_ext
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="Unsupported or invalid image file type",
            )

        # Reject known dangerous prefixes for text formats
        if orig_ext in {"txt", "csv", "json"}:
            for prefix in DANGEROUS_MAGIC_PREFIXES:
                if header_bytes.lower().startswith(prefix.lower()):
                    raise HTTPException(
                        status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                        detail="Unsupported or invalid image file type",
                    )
            return orig_ext

    raise HTTPException(
        status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        detail="Unsupported or invalid image file type",
    )


def save_upload(file: UploadFile) -> dict:
    """Save UploadFile to the uploads directory and return trusted metadata dictionary.

    Returns:
        A dict containing:
        - 'url': The public URL (string) for the saved file, e.g. '/uploads/<filename>'.
        - 'filename': Sanitized original filename.
        - 'size': Authoritative total size in bytes.
    """
    # Read the first 32 bytes to determine file type from magic bytes
    header = file.file.read(32)
    if not header:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty file",
        )

    orig_filename = file.filename or ""
    # Reject known dangerous prefixes immediately
    for prefix in DANGEROUS_MAGIC_PREFIXES:
        if header.lower().startswith(prefix.lower()):
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="Unsupported or invalid image file type",
            )

    # Determine validated extension
    validated_ext = get_file_ext_from_magic_bytes(header, orig_filename)
    if validated_ext not in ALL_ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported or invalid image file type",
        )

    # Generate storage filename using preserved logic with validated extension
    filename = generate_filename(orig_filename, validated_ext)
    file_path = upload_file_path(filename)
    max_size = get_file_size_limit(validated_ext)

    # Stream file contents to disk and enforce max size
    with open(file_path, "wb") as buffer:
        buffer.write(header)
        total_size = len(header)
        while True:
            chunk = file.file.read(64 * 1024)
            if not chunk:
                break
            total_size += len(chunk)
            if total_size > max_size:
                buffer.close()
                try:
                    os.remove(file_path)
                except OSError:
                    pass
                raise HTTPException(
                    status_code=getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413),
                    detail="File too large",
                )
            buffer.write(chunk)

    # Post-stream content validation for document types
    try:
        if validated_ext in {"docx", "xlsx", "pptx"}:
            validate_ooxml_structure(file_path, validated_ext)
        elif validated_ext == "json":
            validate_json_content(file_path)
        elif validated_ext in {"txt", "csv"}:
            validate_text_content(file_path, validated_ext)
    except Exception:
        try:
            os.remove(file_path)
        except OSError:
            pass
        raise

    # Store trusted upload metadata sidecar for server-authoritative filename resolution
    safe_name = sanitize_original_filename(orig_filename, validated_ext)
    meta_path = get_metadata_path_for_file(filename)
    meta_data = {
        "original_filename": safe_name,
        "size": total_size,
        "ext": validated_ext,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        with open(meta_path, "w", encoding="utf-8") as mf:
            json.dump(meta_data, mf)
    except Exception:
        pass

    upload_url = upload_url_for_filename(filename)
    return {
        "url": upload_url,
        "filename": safe_name,
        "size": total_size,
    }

