"""
Pydantic schemas shared across microservices.
UserResponse and DeviceResponse match the monolith's schemas.
"""

import uuid
from datetime import datetime
from pydantic import BaseModel, Field


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    name: str | None
    plan: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class DeviceResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    name: str
    public_key: str
    last_ip: str | None
    last_port: int | None
    nat_type: str
    os: str | None
    version: str | None
    online: bool
    last_seen: datetime
    created_at: datetime

    model_config = {"from_attributes": True}
