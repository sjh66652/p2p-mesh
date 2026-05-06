"""
Pydantic schemas for user-service API requests and responses.
"""

import uuid
from datetime import datetime
from pydantic import BaseModel, Field

from shared.app.schemas_base import UserResponse, DeviceResponse


class DeviceRegister(BaseModel):
    name: str = Field(max_length=128)
    public_key: str
    os: str | None = Field(None, max_length=64)
    version: str | None = Field(None, max_length=32)


class DeviceHeartbeat(BaseModel):
    nat_type: str | None = None
    last_ip: str | None = Field(None, max_length=45)
    last_port: int | None = None


class DeviceListResponse(BaseModel):
    devices: list[DeviceResponse]
    total: int


class UserUpdate(BaseModel):
    """Only non-privileged fields can be updated."""
    name: str | None = Field(None, max_length=128)
