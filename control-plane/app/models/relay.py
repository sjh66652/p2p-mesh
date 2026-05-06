"""
Relay node model - intermediate forwarding servers in the mesh network.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import String, DateTime, Float, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class RelayStatus:
    ONLINE = "online"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"
    OVERLOADED = "overloaded"


class RelayNode(Base):
    __tablename__ = "relay_nodes"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    port: Mapped[int] = mapped_column(default=51820, nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    load: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    max_capacity: Mapped[int] = mapped_column(default=1000, nullable=False)
    current_connections: Mapped[int] = mapped_column(default=0, nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), default=RelayStatus.ONLINE, nullable=False
    )
    public_key: Mapped[str | None] = mapped_column(nullable=True)
    bandwidth_capacity_mbps: Mapped[float] = mapped_column(Float, default=1000.0)
    bandwidth_used_mbps: Mapped[float] = mapped_column(Float, default=0.0)
    last_heartbeat: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
