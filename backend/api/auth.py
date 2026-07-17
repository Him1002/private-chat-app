from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta, UTC

from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.security import pwd_context, verify_password, create_access_token, get_current_user
from backend.db.database import get_db
from backend.db.models import User

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(
    data: LoginRequest,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == data.username).first()

    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return {"access_token": token}


@router.post("/register")
def register(
    data: LoginRequest,
    db: Session = Depends(get_db)
):
    # 1. Check if username exists
    existing_user = db.query(User).filter(User.username == data.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")

    # 2. Create new user
    new_user = User(
        username=data.username,
        password_hash=pwd_context.hash(data.password),
        last_seen=datetime.now(UTC)
    )
    db.add(new_user)
    db.commit()

    return {"msg": "User created successfully"}


@router.get("/me")
def read_me(username: str = Depends(get_current_user)):
    return {"username": username}
