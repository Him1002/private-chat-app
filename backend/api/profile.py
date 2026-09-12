from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.core.security import get_current_user
from backend.db.database import get_db
from backend.db.models import User

router = APIRouter(prefix="/profile", tags=["profile"])


class ProfileUpdate(BaseModel):
    display_name: str | None = None
    about: str | None = None


class ProfilePictureUpdate(BaseModel):
    profile_picture: str | None = None


@router.get("/")
def get_profile(
    current_user: User = Depends(get_current_user)
):
    """Get the current user's profile."""
    return {
        "username": current_user.username,
        "display_name": current_user.display_name,
        "about": current_user.about,
        "profile_picture": current_user.profile_picture
    }


@router.put("/")
def update_profile(
    data: ProfileUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update display name and about."""
    if data.display_name is not None:
        current_user.display_name = data.display_name
    if data.about is not None:
        current_user.about = data.about
        
    db.commit()
    db.refresh(current_user)
    
    return {
        "msg": "Profile updated",
        "profile": {
            "display_name": current_user.display_name,
            "about": current_user.about
        }
    }


@router.put("/picture")
def update_profile_picture(
    data: ProfilePictureUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update profile picture URL."""
    if data.profile_picture is not None:
        current_user.profile_picture = data.profile_picture
        db.commit()
        db.refresh(current_user)
        
    return {
        "msg": "Profile picture updated",
        "profile_picture": current_user.profile_picture
    }
