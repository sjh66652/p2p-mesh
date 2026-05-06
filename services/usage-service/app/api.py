"""
Usage Service API routes.
Enforces plan limits, tracks usage, and prevents abuse.
"""

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

from app.database import get_db, get_redis
from app.dependencies import (
    get_current_user,
    verify_internal_service,
    require_admin,
)
from app.schemas import RecordUsageRequest, ChangePlanRequest
from app import service as usage_service
from app.config import settings

router = APIRouter()


# ---- Internal: Record Usage ----

@router.post("/record", dependencies=[Depends(verify_internal_service)])
async def record_usage(
    data: RecordUsageRequest,
    db: AsyncSession = Depends(get_db),
    redis_client: Redis = Depends(get_redis),
):
    """
    Record a usage event. Internal endpoint — only callable by other services
    via X-Internal-API-Key header. Used to track API requests, WebSocket
    connections, bandwidth, and relay bytes per user.
    """
    await usage_service.record_usage(
        db, redis_client,
        user_id=data.user_id,
        metric_type=data.metric_type,
        value=data.value,
    )
    return {"status": "recorded"}


# ---- Quota Checking ----

@router.get("/quota/{user_id}")
async def check_user_quota(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    redis_client: Redis = Depends(get_redis),
    user: dict = Depends(require_admin),
):
    """
    Check quota for a specific user. Admin only.
    Returns whether the user is within their plan limits.
    """
    result = await usage_service.check_quota(db, redis_client, user_id)
    return result


@router.post("/quota/check")
async def check_self_quota(
    db: AsyncSession = Depends(get_db),
    redis_client: Redis = Depends(get_redis),
    user: dict = Depends(get_current_user),
):
    """
    Check quota for the currently authenticated user.
    Used by API gateway before processing requests.
    """
    result = await usage_service.check_quota(db, redis_client, user["id"])
    return result


# ---- Usage Summary ----

@router.get("/summary/{user_id}")
async def get_usage_summary(
    user_id: uuid.UUID,
    period: str = Query("24h", description="Time period: 24h, 7d, 30d, custom"),
    start: datetime | None = Query(None, description="Custom period start (ISO 8601)"),
    end: datetime | None = Query(None, description="Custom period end (ISO 8601)"),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """
    Get usage summary for a specific user and time period.
    Users can only view their own summary; admins can view any.
    """
    # Authorization: self or admin
    if user["id"] != user_id and user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only view your own usage summary",
        )

    now = datetime.now(timezone.utc)
    if period == "24h":
        start_dt = now - timedelta(hours=24)
        end_dt = now
    elif period == "7d":
        start_dt = now - timedelta(days=7)
        end_dt = now
    elif period == "30d":
        start_dt = now - timedelta(days=30)
        end_dt = now
    elif period == "custom":
        if not start or not end:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Custom period requires both start and end parameters",
            )
        start_dt = start
        end_dt = end
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid period: {period}. Use 24h, 7d, 30d, or custom.",
        )

    summary = await usage_service.get_usage_summary(db, user_id, start_dt, end_dt)
    return summary


# ---- Ban / Unban (Admin) ----

@router.post("/ban/{user_id}", dependencies=[Depends(require_admin)])
async def ban_abusive_user(
    user_id: uuid.UUID,
    reason: str = Query("abuse", description="Reason for the ban"),
    db: AsyncSession = Depends(get_db),
    redis_client: Redis = Depends(get_redis),
    user: dict = Depends(get_current_user),
):
    """Ban a user for abuse. Admin only."""
    await usage_service.ban_user(db, redis_client, user_id, reason=reason)
    return {"status": "banned", "user_id": str(user_id), "reason": reason}


@router.post("/unban/{user_id}", dependencies=[Depends(require_admin)])
async def unban_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    redis_client: Redis = Depends(get_redis),
    user: dict = Depends(get_current_user),
):
    """Remove a ban from a user. Admin only."""
    await usage_service.unban_user(db, redis_client, user_id)
    return {"status": "unbanned", "user_id": str(user_id)}


# ---- Plan Management ----

@router.get("/plans")
async def list_plans():
    """List available plan tiers and their resource limits."""
    return {"plans": usage_service.PLAN_LIMITS}


@router.post("/plan/{user_id}", dependencies=[Depends(require_admin)])
async def change_user_plan(
    user_id: uuid.UUID,
    data: ChangePlanRequest,
    db: AsyncSession = Depends(get_db),
    redis_client: Redis = Depends(get_redis),
    user: dict = Depends(get_current_user),
):
    """Change a user's plan. Admin only."""
    try:
        plan = await usage_service.change_user_plan(db, user_id, data.plan)
        return {
            "user_id": str(plan.user_id),
            "plan": plan.plan,
            "limits": {
                "max_requests_per_min": plan.max_requests_per_min,
                "max_connections": plan.max_connections,
                "max_bandwidth_per_day_bytes": plan.max_bandwidth_per_day_bytes,
            },
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
