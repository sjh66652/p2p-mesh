"""
Pydantic schemas for auth-service API requests and responses.
"""

import uuid
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field

from shared.app.schemas_base import UserResponse


class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    name: str | None = Field(None, max_length=128)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: str | None = None


class RefreshRequest(BaseModel):
    refresh_token: str


class UserUpdate(BaseModel):
    """Only non-privileged fields can be updated by the user.
    Plan and role changes require admin intervention."""
    name: str | None = Field(None, max_length=128)


class PasswordChange(BaseModel):
    old_password: str
    new_password: str = Field(min_length=8, max_length=128)
