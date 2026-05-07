"""
Network models — Virtual IP assignments, ACL policies, route tables.

These support the Phase 1 overlay network features:
- virtual_ips: device -> overlay IP mapping
- route_table: overlay network routes
- acl_policies: stored ACL policy documents
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, Integer, JSON, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, INET

from app.database import Base


class VirtualIP(Base):
    """Virtual IP address assignment for overlay network.

    Each device gets a single IPv4 address from 100.64.0.0/10 (RFC 6598 CGNAT space).
    IP addresses are unique across the mesh network.
    """
    __tablename__ = "virtual_ips"

    device_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    virtual_ip = Column(INET, unique=True, nullable=False, index=True)
    allocated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    released_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(20), default="active")  # active, released, reserved


class RouteEntry(Base):
    """Overlay network route entries.

    Stores routes for the overlay routing table.
    Each route maps a CIDR to a peer device.
    """
    __tablename__ = "route_table"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cidr = Column(INET, nullable=False)
    peer_device_id = Column(UUID(as_uuid=True), nullable=False)
    metric = Column(Integer, default=10)
    admin_distance = Column(Integer, default=1)
    route_type = Column(String(20), default="mesh")  # direct, static, mesh, default
    active = Column(Integer, default=1)  # 1 = active, 0 = inactive
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("cidr", "peer_device_id", name="uq_cidr_peer"),
    )


class AclPolicyStore(Base):
    """Stored ACL policy documents.

    Each row represents a versioned ACL policy for the mesh network.
    The active policy is the most recent version with status='active'.
    """
    __tablename__ = "acl_policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    version = Column(Integer, default=1)
    policy_json = Column(JSON, nullable=False)
    status = Column(String(20), default="active")  # active, draft, archived
    created_by = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    comment = Column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("version", name="uq_acl_version"),
    )
