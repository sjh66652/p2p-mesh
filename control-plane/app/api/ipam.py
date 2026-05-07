"""
IPAM (IP Address Management) API — Virtual IP allocation for overlay network.

Manages virtual IP assignments from the 100.64.0.0/10 (RFC 6598) space.
Each device gets a single /32 IPv4 address in the overlay network.

Endpoints:
- POST /api/v1/network/ipam/allocate — allocate a virtual IP
- POST /api/v1/network/ipam/release — release a virtual IP
- GET /api/v1/network/ipam/{device_id} — get device's virtual IP
- GET /api/v1/network/ipam/peers — list all peer IPs
"""

import ipaddress
from uuid import UUID, uuid4
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from app.database import get_db
from app.dependencies import get_current_user_id
from app.models.user import User

import logging
log = logging.getLogger("p2p-mesh.ipam")

router = APIRouter(tags=["IPAM"])

# Overlay network prefix (RFC 6598 CGNAT space, shared with Tailscale/ZeroTier)
OVERLAY_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")
OVERLAY_HOSTS = list(OVERLAY_NETWORK.hosts())  # ~4M addresses


class AllocateRequest(BaseModel):
    """Request to allocate a virtual IP."""
    device_id: str = Field(..., min_length=1, max_length=64, description="Device UUID")


class AllocateResponse(BaseModel):
    """Response with allocated virtual IP."""
    device_id: str
    virtual_ip: str
    assigned_at: str


class ReleaseRequest(BaseModel):
    """Request to release a virtual IP."""
    device_id: str = Field(..., min_length=1, max_length=64)


class PeerInfo(BaseModel):
    """Peer device information with virtual IP."""
    device_id: str
    virtual_ip: str
    assigned_at: str


class PeersResponse(BaseModel):
    """List of all peer virtual IPs."""
    peers: list[PeerInfo]
    total: int


# In-memory IP allocation table (PostgreSQL-backed in production)
# device_id -> (virtual_ip, assigned_at)
_assigned_ips: dict[str, tuple[str, str]] = {}
# virtual_ip -> device_id
_ip_to_device: dict[str, str] = {}
# Next available host index in OVERLAY_HOSTS
_next_host_idx: int = 0


async def _ensure_ipam_table(db: AsyncSession):
    """Ensure the virtual_ips table exists (compatible with existing migrations)."""
    try:
        await db.execute(text("""
            CREATE TABLE IF NOT EXISTS virtual_ips (
                device_id UUID PRIMARY KEY,
                virtual_ip INET UNIQUE NOT NULL,
                assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        """))
        await db.commit()
        log.info("virtual_ips table ensured")
    except Exception as e:
        log.debug("virtual_ips table may already exist: %s", e)
        await db.rollback()


def _get_next_available_ip() -> str | None:
    """Get the next available IP from the overlay prefix, avoiding conflicts."""
    global _next_host_idx
    used_ips = set(_assigned_ips.values())
    used_ip_strs = {ip for ip, _ in used_ips}

    for _ in range(len(OVERLAY_HOSTS)):
        idx = _next_host_idx % len(OVERLAY_HOSTS)
        candidate = str(OVERLAY_HOSTS[idx])
        _next_host_idx = (idx + 1) % len(OVERLAY_HOSTS)

        if candidate not in used_ip_strs:
            return candidate

    return None


@router.post(
    "/allocate",
    response_model=AllocateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Allocate a virtual IP for a device",
)
async def allocate_ip(
    request: AllocateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Assign a virtual IP from the 100.64.0.0/10 overlay network to a device.

    If the device already has an IP assigned, returns the existing assignment.
    Otherwise, allocates the next available IP address.
    """
    device_id = request.device_id

    # Check if device already has an IP
    if device_id in _assigned_ips:
        ip, assigned = _assigned_ips[device_id]
        log.info("IPAM: Returning existing IP %s for device %s", ip, device_id)
        return AllocateResponse(
            device_id=device_id,
            virtual_ip=ip,
            assigned_at=assigned,
        )

    # Allocate new IP
    ip = _get_next_available_ip()
    if ip is None:
        log.error("IPAM: No available IPs in overlay range")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No available IP addresses in overlay range — pool exhausted",
        )

    now = datetime.now(timezone.utc).isoformat()
    _assigned_ips[device_id] = (ip, now)
    _ip_to_device[ip] = device_id

    # Persist to PostgreSQL
    try:
        await _ensure_ipam_table(db)
        await db.execute(text("""
            INSERT INTO virtual_ips (device_id, virtual_ip, assigned_at)
            VALUES (:device_id, :virtual_ip, NOW())
            ON CONFLICT (device_id) DO UPDATE SET virtual_ip = EXCLUDED.virtual_ip
        """), {
            "device_id": device_id,
            "virtual_ip": ip,
        })
        await db.commit()
    except Exception as e:
        log.warning("IPAM: Failed to persist IP to PostgreSQL (non-fatal): %s", e)
        await db.rollback()

    log.info("IPAM: Allocated %s to device %s", ip, device_id)
    return AllocateResponse(
        device_id=device_id,
        virtual_ip=ip,
        assigned_at=now,
    )


@router.post(
    "/release",
    status_code=status.HTTP_200_OK,
    summary="Release a device's virtual IP",
)
async def release_ip(
    request: ReleaseRequest,
    db: AsyncSession = Depends(get_db),
):
    """Release a device's virtual IP back to the pool.

    Called when a device gracefully shuts down or is deregistered.
    """
    device_id = request.device_id

    if device_id in _assigned_ips:
        ip, _ = _assigned_ips.pop(device_id)
        _ip_to_device.pop(ip, None)

        # Remove from PostgreSQL
        try:
            await db.execute(text("""
                DELETE FROM virtual_ips WHERE device_id = :device_id
            """), {"device_id": device_id})
            await db.commit()
        except Exception:
            await db.rollback()

        log.info("IPAM: Released %s from device %s", ip, device_id)
        return {"status": "released", "device_id": device_id, "virtual_ip": ip}

    log.warning("IPAM: Device %s had no IP to release", device_id)
    return {"status": "not_found", "device_id": device_id}


@router.get(
    "/{device_id}",
    response_model=AllocateResponse,
    summary="Get device's virtual IP",
)
async def get_device_ip(device_id: str):
    """Look up a device's assigned virtual IP address."""
    if device_id in _assigned_ips:
        ip, assigned = _assigned_ips[device_id]
        return AllocateResponse(
            device_id=device_id,
            virtual_ip=ip,
            assigned_at=assigned,
        )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"No IP assigned to device {device_id}",
    )


@router.get(
    "/peers",
    response_model=PeersResponse,
    summary="List all peer virtual IPs",
)
async def list_peers():
    """Get the full mapping of device_id -> virtual_ip for all peers."""
    peers = [
        PeerInfo(
            device_id=dev_id,
            virtual_ip=ip,
            assigned_at=assigned,
        )
        for dev_id, (ip, assigned) in _assigned_ips.items()
    ]

    return PeersResponse(
        peers=peers,
        total=len(peers),
    )
