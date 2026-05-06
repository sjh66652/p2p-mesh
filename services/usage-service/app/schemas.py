"""
Pydantic schemas for Usage Service API.
"""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class UsageReport(BaseModel):
    """A single usage event to be recorded."""
    user_id: uuid.UUID
    metric_type: str = Field(..., pattern=r"^(api_request|ws_connection|bandwidth|relay_bytes)$")
    value: int = Field(default=1, ge=0)
    timestamp: Optional[datetime] = None


class UsageSummary(BaseModel):
    """Aggregated usage summary for a time period."""
    user_id: uuid.UUID
    total_requests: int = 0
    total_bandwidth_bytes: int = 0
    total_connections: int = 0
    period_start: datetime
    period_end: datetime


class QuotaCheckResponse(BaseModel):
    """Result of a quota check."""
    allowed: bool
    reason: str
    current_usage: dict
    limits: dict


class PlanResponse(BaseModel):
    """User's current plan and limits."""
    user_id: uuid.UUID
    plan: str
    limits: dict


class AbuseReport(BaseModel):
    """Report of abuse violations for a user."""
    user_id: uuid.UUID
    violations: list


class RecordUsageRequest(BaseModel):
    """Internal request to record a usage event."""
    user_id: uuid.UUID
    metric_type: str = Field(..., pattern=r"^(api_request|ws_connection|bandwidth|relay_bytes)$")
    value: int = Field(default=1, ge=0)


class ChangePlanRequest(BaseModel):
    """Admin request to change a user's plan."""
    plan: str = Field(..., pattern=r"^(FREE|PRO|ENTERPRISE)$")
