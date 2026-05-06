"""Pydantic schemas for traffic and billing API requests and responses."""

import uuid
from datetime import datetime
from pydantic import BaseModel, Field


class TrafficReport(BaseModel):
    """Traffic usage report from a Rust data node."""
    device_id: uuid.UUID
    peer_device_id: uuid.UUID | None = None
    bytes_sent: int = Field(ge=0)
    bytes_received: int = Field(ge=0)
    connection_type: str = Field(default="p2p")  # p2p or relay
    relay_node_id: uuid.UUID | None = None
    session_start: datetime | None = None
    session_end: datetime | None = None


class TrafficReportBatch(BaseModel):
    """Batch of traffic reports for efficient processing."""
    reports: list[TrafficReport]


class TrafficSummary(BaseModel):
    """Aggregated traffic summary for a user."""
    total_bytes_sent: int
    total_bytes_received: int
    p2p_bytes: int
    relay_bytes: int
    period_start: datetime
    period_end: datetime


class SubscriptionCreate(BaseModel):
    plan: str
    payment_method: str | None = None


class SubscriptionResponse(BaseModel):
    id: uuid.UUID
    plan: str
    status: str
    started_at: datetime
    expires_at: datetime | None
    auto_renew: bool

    model_config = {"from_attributes": True}


class InvoiceResponse(BaseModel):
    id: uuid.UUID
    amount_cents: int
    currency: str
    status: str
    billing_period_start: datetime
    billing_period_end: datetime
    created_at: datetime
    paid_at: datetime | None

    model_config = {"from_attributes": True}
