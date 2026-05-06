"""Relay node management API routes."""

import uuid
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.services import relay_service

router = APIRouter()


class RelayRegisterRequest(BaseModel):
    name: str = Field(max_length=128)
    ip: str = Field(max_length=45)
    port: int = Field(default=51820)
    region: str = Field(max_length=64)
    public_key: str | None = None
    max_capacity: int = Field(default=1000)
    bandwidth_capacity_mbps: float = Field(default=1000.0)


class RelayHeartbeatRequest(BaseModel):
    load: float
    current_connections: int
    bandwidth_used_mbps: float = 0.0


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


@router.get("")
async def list_relays(
    region: str | None = Query(None),
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all relay nodes, optionally filtered by region."""
    relays = await relay_service.get_all_relays(db, region=region)
    return {
        "relays": [
            {
                "id": str(r.id),
                "name": r.name,
                "ip": r.ip,
                "port": r.port,
                "region": r.region,
                "load": r.load,
                "status": r.status,
                "current_connections": r.current_connections,
                "bandwidth_used_mbps": r.bandwidth_used_mbps,
            }
            for r in relays
        ],
        "total": len(relays),
    }


@router.post("", status_code=status.HTTP_201_CREATED)
async def register_relay(
    data: RelayRegisterRequest,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Register a new relay node (admin operation)."""
    try:
        relay = await relay_service.register_relay(
            db,
            name=data.name,
            ip=data.ip,
            port=data.port,
            region=data.region,
            public_key=data.public_key,
            max_capacity=data.max_capacity,
            bandwidth_capacity_mbps=data.bandwidth_capacity_mbps,
        )
        return {"id": str(relay.id), "status": relay.status}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.post("/{relay_id}/heartbeat")
async def relay_heartbeat(
    relay_id: str,
    data: RelayHeartbeatRequest,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update relay node health status (called by relay nodes)."""
    try:
        relay = await relay_service.update_heartbeat(
            db,
            uuid.UUID(relay_id),
            load=data.load,
            current_connections=data.current_connections,
            bandwidth_used_mbps=data.bandwidth_used_mbps,
        )
        return {"status": relay.status}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.delete("/{relay_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_relay(
    relay_id: str,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove a relay node (admin operation)."""
    try:
        await relay_service.delete_relay(db, uuid.UUID(relay_id))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
