"""
SQLAlchemy ORM models for Usage Service.
Tracks usage metrics, user plans, and rolling window counters for rate limiting.
"""

import uuid
from datetime import datetime

from sqlalchemy import Column, String, Integer, BigInteger, DateTime, Boolean, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase
import enum


class Base(DeclarativeBase):
    pass


class PlanTier(str, enum.Enum):
    FREE = "FREE"
    PRO = "PRO"
    ENTERPRISE = "ENTERPRISE"


class UserPlan(Base):
    """User plan and enforcement state."""

    __tablename__ = "usage_plans"

    user_id = Column(UUID(as_uuid=True), primary_key=True)
    plan = Column(String(20), default=PlanTier.FREE.value, nullable=False)
    max_requests_per_min = Column(Integer, default=100)
    max_connections = Column(Integer, default=3)
    max_bandwidth_per_day_bytes = Column(BigInteger, default=1_073_741_824)  # 1GB
    is_banned = Column(Boolean, default=False)
    banned_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


class UsageRecord(Base):
    """Immutable usage event log for audit and historical analysis."""

    __tablename__ = "usage_records"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    metric_type = Column(String(50), nullable=False)  # 'api_request', 'ws_connection', 'bandwidth', 'relay_bytes'
    value = Column(BigInteger, default=0)
    timestamp = Column(DateTime, server_default=func.now(), index=True)


class UsageWindow(Base):
    """Rolling window counters for rate limiting queries."""

    __tablename__ = "usage_windows"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    window_start = Column(DateTime, nullable=False)
    window_end = Column(DateTime, nullable=False)
    requests_count = Column(Integer, default=0)
    bandwidth_bytes = Column(BigInteger, default=0)
    ws_connections = Column(Integer, default=0)
