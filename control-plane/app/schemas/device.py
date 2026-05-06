"""Pydantic schemas for device-related API requests and responses."""

import uuid
from datetime import datetime
from pydantic import BaseModel, Field


class DeviceRegister(BaseModel):
    name: str = Field(max_length=128)
    public_key: str
    os: str | None = Field(None, max_length=64)
    version: str | None = Field(None, max_length=32)


class DeviceHeartbeat(BaseModel):
    nat_type: str | None = None
    last_ip: str | None = Field(None, max_length=45)
    last_port: int | None = None


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


class DeviceListResponse(BaseModel):
    devices: list[DeviceResponse]
    total: int


class SignalingRequest(BaseModel):
    """Request to initiate a signaling session between two devices."""
    from_device_id: uuid.UUID
    to_device_id: uuid.UUID
    sdp_offer: str | None = None  # WebRTC SDP
    candidates: list[str] = Field(default_factory=list)  # ICE candidates
