from fastapi import APIRouter, UploadFile, File, Depends
from fastapi.staticfiles import StaticFiles

from backend.core.config import settings
from backend.core.security import get_current_user
from backend.db.models import User

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


def register_uploads(app):
    """Mount the uploads static directory on the FastAPI app.

    Separated into a function so the main application can call it after
    importing this module. This preserves the original app.mount call
    that lived in main.py.
    """
    app.mount("/uploads", StaticFiles(directory=settings.UPLOADS_DIR), name="uploads")
