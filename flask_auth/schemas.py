from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime

class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    user: dict

class RefreshTokenResponse(BaseModel):
    access_token: str

class MessageResponse(BaseModel):
    message: str

class ErrorResponse(BaseModel):
    error: str

