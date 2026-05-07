"""Network scheduling API routes - path selection, P2P feasibility checks."""

import uuid
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.services.network_service import choose_path, can_p2p

router = APIRouter()


@router.get("/path")
async def find_path(
    device_a: str = Query(..., description="Device A ID"),
    device_b: str = Query(..., description="Device B ID"),
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Determine the optimal path between two devices.
    Returns "p2p" for direct connection or "relay" with relay node details.
    """
    from app.services.device_service import get_device_by_id

    try:
        dev_a = await get_device_by_id(db, uuid.UUID(device_a))
        dev_b = await get_device_by_id(db, uuid.UUID(device_b))
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid device ID format",
        )

    if not dev_a or not dev_b:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="One or both devices not found",
        )

    # Both devices must belong to the current user.
    # Previously allowed "at least one" which leaked routing info about
    # other users' devices (IP, region) when combined with path selection.
    if dev_a.user_id != user.id or dev_b.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Both devices must belong to you",
        )

    result = await choose_path(
        db,
        device_a_ip=dev_a.last_ip or "0.0.0.0",  # nosec B104  # fallback when device IP unknown
        device_a_nat=dev_a.nat_type,
        device_b_ip=dev_b.last_ip or "0.0.0.0",  # nosec B104  # fallback when device IP unknown
        device_b_nat=dev_b.nat_type,
    )

    return {
        "path_type": result.path_type,
        "relay_node_id": str(result.relay_node_id) if result.relay_node_id else None,
        "relay_ip": result.relay_ip if user.role.value == "admin" else "***",
        "relay_port": result.relay_port,
        "reason": result.reason,
    }


@router.get("/check-nat")
async def check_nat_compatibility(
    nat_a: str = Query(..., description="NAT type of device A"),
    nat_b: str = Query(..., description="NAT type of device B"),
):
    """Check if two NAT types are compatible for direct P2P."""
    return {
        "p2p_possible": can_p2p(nat_a, nat_b),
        "nat_a": nat_a,
        "nat_b": nat_b,
    }
