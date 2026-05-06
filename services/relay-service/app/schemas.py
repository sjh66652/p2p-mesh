"""
Pydantic schemas for relay node API request/response validation.
"""

import uuid

from pydantic import BaseModel, Field


class RelayRegisterRequest(BaseModel):
    name: str = Field(max_length=128)
    ip: str = Field(max_length=45)
    port: int = Field(default=51820)
    region: str = Field(max_length=64)
    public_key: str | None = None
    max_capacity: int = Field(default=1000, ge=1, le=100000)
    bandwidth_capacity_mbps: float = Field(default=1000.0, ge=1.0)


class RelayHeartbeatRequest(BaseModel):
    load: float = Field(ge=0.0, le=1.0)
    current_connections: int = Field(ge=0)
    bandwidth_used_mbps: float = Field(ge=0.0)


class RelayResponse(BaseModel):
    id: uuid.UUID
    name: str
    ip: str
    port: int
    region: str
    load: float
    max_capacity: int
    current_connections: int
    status: str
    bandwidth_capacity_mbps: float
    bandwidth_used_mbps: float
    last_heartbeat: str | None
    created_at: str

    model_config = {"from_attributes": True}


class RelayPublicResponse(BaseModel):
    """Relay response with IP hidden for non-admin users."""
    id: uuid.UUID
    name: str
    port: int
    region: str
    load: float
    status: str
    current_connections: int
    bandwidth_used_mbps: float

    model_config = {"from_attributes": True}


class BestRelayResponse(BaseModel):
    id: uuid.UUID
    name: str
    ip: str
    port: int
    region: str
    load: float
    status: str
