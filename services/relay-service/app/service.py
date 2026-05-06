"""
Relay node management service - registration, health checks, and load balancing.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.config import settings
from app.models import RelayNode, RelayStatus

logger = logging.getLogger(__name__)


async def register_relay(
    db: AsyncSession,
    name: str,
    ip: str,
    port: int,
    region: str,
    public_key: str | None = None,
    max_capacity: int = 1000,
    bandwidth_capacity_mbps: float = 1000.0,
) -> RelayNode:
    """Register a new relay node in the network."""
    existing = await db.execute(
        select(RelayNode).where(
            RelayNode.ip == ip,
            RelayNode.port == port,
        )
    )
    if existing.scalar_one_or_none():
        raise ValueError(f"Relay node {ip}:{port} already exists")

    relay = RelayNode(
        name=name,
        ip=ip,
        port=port,
        region=region,
        public_key=public_key,
        max_capacity=max_capacity,
        bandwidth_capacity_mbps=bandwidth_capacity_mbps,
        status=RelayStatus.ONLINE,
    )
    db.add(relay)
    await db.flush()
    await db.refresh(relay)
    return relay


async def get_all_relays(
    db: AsyncSession, region: str | None = None
) -> list[RelayNode]:
    """Get all relay nodes, optionally filtered by region."""
    query = select(RelayNode).order_by(RelayNode.load.asc())
    if region:
        query = query.where(RelayNode.region == region)
    result = await db.execute(query)
    return list(result.scalars().all())


async def get_relay_by_id(
    db: AsyncSession, relay_id: uuid.UUID
) -> RelayNode | None:
    """Get a relay node by its ID."""
    result = await db.execute(
        select(RelayNode).where(RelayNode.id == relay_id)
    )
    return result.scalar_one_or_none()


async def update_heartbeat(
    db: AsyncSession,
    relay_id: uuid.UUID,
    load: float,
    current_connections: int,
    bandwidth_used_mbps: float,
) -> RelayNode:
    """Update relay node status via heartbeat."""
    relay = await get_relay_by_id(db, relay_id)
    if not relay:
        raise ValueError("Relay node not found")

    relay.load = load
    relay.current_connections = current_connections
    relay.bandwidth_used_mbps = bandwidth_used_mbps
    relay.last_heartbeat = datetime.now(timezone.utc)

    # Auto-status update based on load
    if load > settings.RELAY_MAX_LOAD:
        relay.status = RelayStatus.OVERLOADED
    else:
        relay.status = RelayStatus.ONLINE

    await db.flush()
    await db.refresh(relay)
    return relay


async def heartbeat_by_name(
    db: AsyncSession,
    name: str,
    ip: str,
    port: int,
    region: str,
    load: float,
    current_connections: int,
    bandwidth_used_mbps: float,
    max_capacity: int = 1000,
    bandwidth_capacity_mbps: float = 1000.0,
) -> RelayNode:
    """
    Update relay status via heartbeat, identified by name.
    Auto-registers the relay if it doesn't exist yet.
    This allows relay nodes to self-identify without admin pre-registration.
    """
    # Look up by name first
    result = await db.execute(
        select(RelayNode).where(RelayNode.name == name)
    )
    relay = result.scalar_one_or_none()

    if relay is None:
        # Auto-register: relay node has valid RELAY_AUTH_TOKEN, so it's trusted
        relay = RelayNode(
            name=name,
            ip=ip,
            port=port,
            region=region,
            max_capacity=max_capacity,
            bandwidth_capacity_mbps=bandwidth_capacity_mbps,
            status=RelayStatus.ONLINE,
        )
        db.add(relay)
        await db.flush()
        logger.info(
            "Auto-registered relay: name=%s ip=%s region=%s", name, ip, region
        )

    relay.load = load
    relay.current_connections = current_connections
    relay.bandwidth_used_mbps = bandwidth_used_mbps
    relay.last_heartbeat = datetime.now(timezone.utc)

    if load > settings.RELAY_MAX_LOAD:
        relay.status = RelayStatus.OVERLOADED
    else:
        relay.status = RelayStatus.ONLINE

    await db.flush()
    await db.refresh(relay)
    return relay


async def set_relay_status(
    db: AsyncSession, relay_id: uuid.UUID, status: str
) -> RelayNode:
    """Manually update relay node status (e.g., maintenance mode)."""
    relay = await get_relay_by_id(db, relay_id)
    if not relay:
        raise ValueError("Relay node not found")

    relay.status = status
    await db.flush()
    await db.refresh(relay)
    return relay


async def delete_relay(db: AsyncSession, relay_id: uuid.UUID):
    """Remove a relay node from the network."""
    relay = await get_relay_by_id(db, relay_id)
    if not relay:
        raise ValueError("Relay node not found")
    await db.delete(relay)
    await db.flush()


async def cleanup_stale_relays(db: AsyncSession):
    """
    Background task: mark relay nodes as offline if they haven't
    sent a heartbeat within the cleanup interval.
    """
    now = datetime.now(timezone.utc)
    stale_threshold = now - timedelta(seconds=settings.RELAY_CLEANUP_INTERVAL)

    await db.execute(
        update(RelayNode)
        .where(
            RelayNode.last_heartbeat < stale_threshold,
            RelayNode.status != RelayStatus.MAINTENANCE,
        )
        .values(status=RelayStatus.OFFLINE)
    )
    await db.commit()


async def select_best_relay(
    db: AsyncSession, region: str | None = None
) -> RelayNode | None:
    """
    Select the best relay node based on a scoring algorithm.
    Scoring weights: load(50%), bandwidth(30%), capacity(20%).
    Returns None if no suitable relay is available.
    """
    relays = await get_all_relays(db, region=region)

    # Filter to only online relays
    online_relays = [r for r in relays if r.status == RelayStatus.ONLINE]
    if not online_relays:
        return None

    def _score(relay: RelayNode) -> float:
        """Score a relay node (higher is better)."""
        # Load score: lower load is better (inverted)
        load_score = 1.0 - relay.load

        # Bandwidth score: ratio of unused bandwidth
        if relay.bandwidth_capacity_mbps > 0:
            bw_score = 1.0 - (relay.bandwidth_used_mbps / relay.bandwidth_capacity_mbps)
        else:
            bw_score = 0.0

        # Capacity score: ratio of available connections
        if relay.max_capacity > 0:
            cap_score = 1.0 - (relay.current_connections / relay.max_capacity)
        else:
            cap_score = 0.0

        # Weighted combination
        return (load_score * 0.5) + (bw_score * 0.3) + (cap_score * 0.2)

    return max(online_relays, key=_score)


def start_relay_health_check() -> asyncio.Task:
    """
    Start the background relay node health check task.
    Returns a cancellable asyncio Task.
    """
    async def _health_loop():
        from app.database import async_session_factory
        while True:
            await asyncio.sleep(settings.RELAY_CLEANUP_INTERVAL)
            try:
                async with async_session_factory() as session:
                    await cleanup_stale_relays(session)
            except Exception as e:
                logger.error(f"Relay health check failed: {e}")

    return asyncio.create_task(_health_loop())
