"""
Relay node management API routes.

Authorization model:
- list_relays: authenticated users see names/regions/load only (no IPs)
- register_relay: admin-only (human users with admin role)
- relay_heartbeat: relay nodes authenticate via RELAY_AUTH_TOKEN
- delete_relay: admin-only
"""
import uuid
import logging

from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import Response

from app.config import settings
from app.database import get_db, get_redis
from app.dependencies import get_current_user, require_admin, get_relay_auth
from app.schemas import (
    RelayRegisterRequest,
    RelayHeartbeatRequest,
    RelayResponse,
    BestRelayResponse,
)
from app import service as relay_service
from shared.app.usage_middleware import check_usage_quota

logger = logging.getLogger("relay-service.api")
router = APIRouter(dependencies=[Depends(check_usage_quota)])


@router.get("")
async def list_relays(
    region: str | None = Query(None),
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List relay nodes (authenticated users -- IPs hidden for non-admins)."""
    relays = await relay_service.get_all_relays(db, region=region)
    is_admin = user.get("role", "") == "admin"

    return {
        "relays": [
            {
                "id": str(r.id),
                "name": r.name,
                # Only admins see internal IPs
                "ip": r.ip if is_admin else "***",
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
    request: Request,
    admin=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    redis_client=Depends(get_redis),
):
    """Register a new relay node (admin only). Rate-limited per admin IP."""
    # Rate limit relay registration by admin IP
    admin_ip = request.client.host if request.client else "unknown"
    reg_key = f"relay_reg_rate:{admin_ip}"
    reg_count = await redis_client.incr(reg_key)
    if reg_count == 1:
        await redis_client.expire(reg_key, 60)

    if reg_count > settings.RELAY_MAX_REGISTRATION_RATE:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many relay registrations. Try again later.",
        )

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
    request: Request,
    db: AsyncSession = Depends(get_db),
    _relay_token=Depends(get_relay_auth),
):
    """
    Update relay node health status (relay nodes only -- authenticated via shared token).

    Supports two identification modes:
    1. UUID-based: admin pre-registered relay (backward compatible)
    2. Name-based: relay auto-registers on first heartbeat (discovery mode)
    """
    # Get relay's IP from request (X-Real-IP if behind Nginx, else client host)
    relay_ip = (
        request.headers.get("X-Real-IP")
        or (request.client.host if request.client else "unknown")
    )

    # Phase 1: Is this a UUID or a name?
    # Separate UUID parsing from DB lookup to avoid error ambiguity
    try:
        relay_uuid = uuid.UUID(relay_id)
        is_uuid = True
    except (ValueError, AttributeError):
        is_uuid = False

    if is_uuid:
        try:
            relay = await relay_service.update_heartbeat(
                db,
                relay_uuid,
                load=data.load,
                current_connections=data.current_connections,
                bandwidth_used_mbps=data.bandwidth_used_mbps,
            )
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    else:
        # Name-based lookup with auto-registration
        if not relay_id or len(relay_id) > 128:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid relay identifier",
            )
        try:
            relay = await relay_service.heartbeat_by_name(
                db,
                name=relay_id,
                ip=relay_ip,
                port=51821,  # default relay port; configurable via env in prod
                region="default",
                load=data.load,
                current_connections=data.current_connections,
                bandwidth_used_mbps=data.bandwidth_used_mbps,
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to process relay heartbeat: {e}",
            )

    return {"status": relay.status, "id": str(relay.id)}


@router.delete("/{relay_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_relay(
    relay_id: str,
    admin=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Remove a relay node (admin only)."""
    try:
        relay_uuid = uuid.UUID(relay_id)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Relay ID must be a valid UUID",
        )
    try:
        await relay_service.delete_relay(db, relay_uuid)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/best")
async def get_best_relay(
    region: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Get the best available relay node for a region."""
    relay = await relay_service.select_best_relay(db, region=region)
    if relay is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No suitable relay available",
        )
    return BestRelayResponse(
        id=relay.id,
        name=relay.name,
        ip=relay.ip,
        port=relay.port,
        region=relay.region,
        load=relay.load,
        status=relay.status,
    )

