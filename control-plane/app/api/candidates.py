"""
Candidate exchange API — NAT traversal candidate registration and retrieval.

Phase 1 (NAT Traversal):
- POST /candidates — Register device candidates
- GET /candidates/{peer_id} — Fetch peer candidates for hole punching
- POST /candidates/probe — Submit NAT type probe results
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.schemas.candidate import (
    CandidateRegister, CandidateResponse, CandidateListResponse,
    CandidateEntry, NATProbeRequest, NATProbeResponse,
)
from app.models.device import Device, NATType

logger = logging.getLogger("p2p-mesh.candidates")
router = APIRouter()

# In-memory candidate store (per session).
# For multi-replica production, move to Redis sorted sets.
_candidates: Dict[str, List[dict]] = {}


def _candidate_key(device_id: str) -> str:
    """Normalize device ID to string for storage."""
    return str(device_id)


@router.post("", status_code=status.HTTP_201_CREATED)
async def register_candidates(
    data: CandidateRegister,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Register network candidates for a device after STUN discovery.

    Candidates are stored and made available to peers for NAT hole punching.
    Only the device owner can register candidates for their devices.
    """
    # Verify device ownership
    try:
        dev_uuid = uuid.UUID(data.device_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid device ID format",
        )

    from sqlalchemy import select
    result = await db.execute(
        select(Device).where(
            Device.id == dev_uuid,
            Device.user_id == user.id,
        )
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Device not found or not authorized",
        )

    # Store candidates
    key = _candidate_key(data.device_id)
    _candidates[key] = [
        {
            "addr": c.addr,
            "candidate_type": c.candidate_type,
            "priority": c.priority,
        }
        for c in data.candidates
    ]

    # Update device's last_ip with the first public candidate
    public_candidates = [c for c in data.candidates if c.candidate_type == "srflx"]
    if public_candidates and public_candidates[0].addr:
        ip_port = public_candidates[0].addr.rsplit(":", 1)
        device.last_ip = ip_port[0]
        if len(ip_port) > 1:
            try:
                device.last_port = int(ip_port[1])
            except ValueError:
                pass
        await db.flush()

    logger.info(
        "Candidates registered for device %s: %d candidates (srflx=%d, host=%d)",
        data.device_id,
        len(data.candidates),
        len(public_candidates),
        len([c for c in data.candidates if c.candidate_type == "host"]),
    )

    return {
        "status": "ok",
        "device_id": data.device_id,
        "candidate_count": len(data.candidates),
    }


@router.get("/{peer_id}", response_model=CandidateResponse)
async def get_peer_candidates(
    peer_id: str,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get network candidates for a peer device.

    Only devices belonging to the same user can retrieve each other's
    candidates. This prevents topology information leakage.
    """
    try:
        peer_uuid = uuid.UUID(peer_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid device ID format",
        )

    # Verify the peer device belongs to the same user
    from sqlalchemy import select
    result = await db.execute(
        select(Device).where(
            Device.id == peer_uuid,
            Device.user_id == user.id,
        )
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Peer device not found",
        )

    key = _candidate_key(peer_id)
    candidates = _candidates.get(key, [])

    if not candidates:
        logger.debug("No candidates found for device %s", peer_id)

    return CandidateResponse(
        device_id=peer_id,
        candidates=[
            CandidateEntry(
                addr=c["addr"],
                candidate_type=c["candidate_type"],
                priority=c["priority"],
            )
            for c in candidates
        ],
        updated_at=datetime.now(timezone.utc).isoformat(),
    )


@router.post("/probe", response_model=NATProbeResponse)
async def submit_nat_probe(
    data: NATProbeRequest,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Submit NAT type probe results from a client.

    The client performs multi-server STUN probing and reports the
    results, allowing the control plane to classify the NAT type.
    """
    try:
        dev_uuid = uuid.UUID(data.device_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid device ID format",
        )

    from sqlalchemy import select
    result = await db.execute(
        select(Device).where(
            Device.id == dev_uuid,
            Device.user_id == user.id,
        )
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Device not authorized",
        )

    # Update NAT type based on probe results
    nat_type = classify_nat_from_mapped(data.mapped_addrs)
    device.nat_type = nat_type
    await db.flush()

    logger.info(
        "NAT probe submitted for device %s: type=%s, addresses=%d",
        data.device_id, nat_type, len(data.mapped_addrs),
    )

    return NATProbeResponse(
        device_id=data.device_id,
        nat_type=nat_type,
        mapped_addrs=data.mapped_addrs,
    )


def classify_nat_from_mapped(mapped_addrs: List[str]) -> str:
    """
    Classify NAT type from multi-server STUN probe results.

    Simple heuristic:
    - No results → unknown
    - All same IP:port → full_cone or open
    - Same IP, different ports → symmetric
    """
    if not mapped_addrs:
        return NATType.UNKNOWN

    parsed = []
    for addr in mapped_addrs:
        try:
            ip, port = addr.rsplit(":", 1)
            parsed.append((ip, int(port)))
        except (ValueError, IndexError):
            continue

    if len(parsed) < 1:
        return NATType.UNKNOWN

    if len(parsed) == 1:
        return NATType.FULL_CONE

    # Check if all addresses are identical
    first = parsed[0]
    all_same = all(a == first for a in parsed)

    if all_same:
        return NATType.FULL_CONE

    # Same IP but different ports → symmetric
    same_ip = all(a[0] == first[0] for a in parsed)
    if same_ip:
        return NATType.SYMMETRIC

    return NATType.UNKNOWN
