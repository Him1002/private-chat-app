from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.core.security import get_client_ip, get_current_user
from backend.db.database import get_db
from backend.db.models import User
from backend.services import auth_service

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(
    request: Request,
    data: LoginRequest,
    db: Session = Depends(get_db)
):
    client_ip = get_client_ip(request)
    token = auth_service.authenticate_user(db, data.username, data.password, client_ip)
    return {"access_token": token}


@router.post("/register")
def register(
    request: Request,
    data: LoginRequest,
    db: Session = Depends(get_db)
):
    client_ip = get_client_ip(request)
    auth_service.register_user(db, data.username, data.password, client_ip)
    return {"msg": "User created successfully"}


@router.get("/me")
def read_me(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username}
