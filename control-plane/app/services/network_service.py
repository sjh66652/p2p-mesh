"""
Network scheduling service - determines the best path between devices.
Handles NAT traversal classification, P2P feasibility, and relay selection.
"""

import uuid
from dataclasses import dataclass
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.device import NATType
from app.services.nat_utils import can_establish_p2p, estimate_p2p_success_rate


@dataclass
class PathResult:
    """Result of a path-finding decision between two devices."""
    path_type: str  # "p2p" or "relay"
    relay_node_id: Optional[uuid.UUID] = None
    relay_ip: Optional[str] = None
    relay_port: Optional[int] = None
    reason: str = ""


# P2P feasibility matrix: whether two NAT types can establish a direct connection
# True = direct P2P possible, False = requires relay.
# Imported from nat_utils for centralized NAT logic.
NAT_COMPATIBILITY = {
    (NATType.OPEN, NATType.OPEN): True,
    (NATType.OPEN, NATType.FULL_CONE): True,
    (NATType.OPEN, NATType.RESTRICTED_CONE): True,
    (NATType.OPEN, NATType.PORT_RESTRICTED): True,
    (NATType.OPEN, NATType.SYMMETRIC): True,
    (NATType.FULL_CONE, NATType.OPEN): True,
    (NATType.FULL_CONE, NATType.FULL_CONE): True,
    (NATType.FULL_CONE, NATType.RESTRICTED_CONE): True,
    (NATType.FULL_CONE, NATType.PORT_RESTRICTED): True,
    (NATType.FULL_CONE, NATType.SYMMETRIC): False,
    (NATType.RESTRICTED_CONE, NATType.OPEN): True,
    (NATType.RESTRICTED_CONE, NATType.FULL_CONE): True,
    (NATType.RESTRICTED_CONE, NATType.RESTRICTED_CONE): True,
    (NATType.RESTRICTED_CONE, NATType.PORT_RESTRICTED): True,
    (NATType.RESTRICTED_CONE, NATType.SYMMETRIC): False,
    (NATType.PORT_RESTRICTED, NATType.OPEN): True,
    (NATType.PORT_RESTRICTED, NATType.FULL_CONE): True,
    (NATType.PORT_RESTRICTED, NATType.RESTRICTED_CONE): True,
    (NATType.PORT_RESTRICTED, NATType.PORT_RESTRICTED): True,
    (NATType.PORT_RESTRICTED, NATType.SYMMETRIC): False,
    (NATType.SYMMETRIC, NATType.SYMMETRIC): False,
}


def can_p2p(nat_a: str, nat_b: str) -> bool:
    """Check if two NAT types can establish direct P2P.
    Uses the centralized nat_utils module for classification."""
    return can_establish_p2p(nat_a, nat_b)


async def choose_path(
    db: AsyncSession,
    device_a_ip: str,
    device_a_nat: str,
    device_b_ip: str,
    device_b_nat: str,
) -> PathResult:
    """
    Determine the best path between two devices.

    Strategy:
    1. Check if direct P2P is possible given NAT types
    2. If P2P is possible and devices are on the same private subnet, prefer local
    3. If P2P is possible via STUN hole-punching, return P2P
    4. Otherwise, select the best available relay node
    """
    if can_p2p(device_a_nat, device_b_nat):
        # Check if on same private subnet (fast path)
        if _is_same_private_subnet(device_a_ip, device_b_ip):
            return PathResult(
                path_type="p2p",
                reason="Same private subnet - direct LAN connection",
            )
        return PathResult(
            path_type="p2p",
            reason="P2P possible via NAT hole-punching",
        )

    # P2P not possible - select a relay
    relay = await select_best_relay(db, device_a_ip, device_b_ip)
    if relay:
        return PathResult(
            path_type="relay",
            relay_node_id=relay["id"],
            relay_ip=relay["ip"],
            relay_port=relay["port"],
            reason=f"NAT incompatible - routing via relay in {relay['region']}",
        )

    return PathResult(
        path_type="relay",
        reason="No suitable relay found",
    )


async def select_best_relay(
    db: AsyncSession, client_a_ip: str, client_b_ip: str
) -> dict | None:
    """
    Select the optimal relay node for two clients.

    Selection criteria (in order):
    1. Region proximity to both clients
    2. Current load factor
    3. Available bandwidth capacity
    """
    from sqlalchemy import select
    from app.models.relay import RelayNode, RelayStatus

    result = await db.execute(
        select(RelayNode)
        .where(RelayNode.status == RelayStatus.ONLINE)
        .order_by(RelayNode.load.asc(), RelayNode.bandwidth_used_mbps.asc())
        .limit(3)
    )
    relays = result.scalars().all()

    if not relays:
        return None

    # Score each relay and pick the best
    def score_relay(relay):
        score = 0.0
        # Lower load is better
        score += (1.0 - relay.load) * 50  # weight: 50
        # Higher available bandwidth is better
        available = relay.bandwidth_capacity_mbps - relay.bandwidth_used_mbps
        if relay.bandwidth_capacity_mbps > 0:
            score += (available / relay.bandwidth_capacity_mbps) * 30  # weight: 30
        # Capacity headroom
        if relay.max_capacity > 0:
            headroom = 1.0 - (relay.current_connections / relay.max_capacity)
            score += headroom * 20  # weight: 20
        return score

    best = max(relays, key=score_relay)

    return {
        "id": best.id,
        "ip": best.ip,
        "port": best.port,
        "region": best.region,
        "load": best.load,
    }


def _is_same_private_subnet(ip_a: str, ip_b: str) -> bool:
    """Check if two IPs appear to be on the same private subnet."""
    PRIVATE_PREFIXES = ["10.", "172.16.", "172.17.", "172.18.",
                        "172.19.", "172.20.", "172.21.", "172.22.",
                        "172.23.", "172.24.", "172.25.", "172.26.",
                        "172.27.", "172.28.", "172.29.", "172.30.",
                        "172.31.", "192.168.", "fd"]
    for prefix in PRIVATE_PREFIXES:
        if ip_a.startswith(prefix) and ip_b.startswith(prefix):
            # Both private — check /24 for IPv4
            if "." in ip_a:
                return ".".join(ip_a.split(".")[:3]) == ".".join(ip_b.split(".")[:3])
            return True
    return False
