"""
Core usage service logic.
Tracks usage metrics, enforces plan limits, and prevents abuse.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from redis.asyncio import Redis

from app.models import UsageRecord, UserPlan, PlanTier
from app.config import settings


# ---- Plan Definitions ----

PLAN_LIMITS = {
    PlanTier.FREE.value: {
        "max_requests_per_min": settings.FREE_MAX_REQUESTS_PER_MIN,
        "max_connections": settings.FREE_MAX_CONNECTIONS,
        "max_bandwidth_per_day_gb": settings.FREE_MAX_BANDWIDTH_PER_DAY_GB,
    },
    PlanTier.PRO.value: {
        "max_requests_per_min": settings.PRO_MAX_REQUESTS_PER_MIN,
        "max_connections": settings.PRO_MAX_CONNECTIONS,
        "max_bandwidth_per_day_gb": settings.PRO_MAX_BANDWIDTH_PER_DAY_GB,
    },
    PlanTier.ENTERPRISE.value: {
        "max_requests_per_min": settings.ENTERPRISE_MAX_REQUESTS_PER_MIN,
        "max_connections": settings.ENTERPRISE_MAX_CONNECTIONS,
        "max_bandwidth_per_day_gb": settings.ENTERPRISE_MAX_BANDWIDTH_PER_DAY_GB,
    },
}


async def get_or_create_user_plan(db: AsyncSession, user_id: uuid.UUID) -> UserPlan:
    """Get user's plan, creating a default FREE plan if none exists."""
    result = await db.execute(select(UserPlan).where(UserPlan.user_id == user_id))
    plan = result.scalar_one_or_none()
    if not plan:
        plan = UserPlan(user_id=user_id, plan=PlanTier.FREE.value)
        db.add(plan)
        await db.flush()
    return plan


async def record_usage(
    db: AsyncSession,
    redis_client: Redis,
    user_id: uuid.UUID,
    metric_type: str,
    value: int = 1,
):
    """Record a usage event (API request, WS connection, bandwidth bytes)."""
    # Write to Postgres for persistence
    record = UsageRecord(user_id=user_id, metric_type=metric_type, value=value)
    db.add(record)

    # Update Redis counters for fast quota checks
    now = datetime.now(timezone.utc)
    minute_key = f"usage:minute:{user_id}:{now.strftime('%Y%m%d%H%M')}"
    day_key = f"usage:day:{user_id}:{now.strftime('%Y%m%d')}"

    pipe = redis_client.pipeline()
    if metric_type == "api_request":
        pipe.incrby(f"{minute_key}:requests", value)
        pipe.expire(f"{minute_key}:requests", 120)
    elif metric_type == "ws_connection":
        pipe.incrby(f"{day_key}:connections", value)
        pipe.expire(f"{day_key}:connections", 86400 * 2)
    elif metric_type in ("bandwidth", "relay_bytes"):
        pipe.incrby(f"{day_key}:bandwidth", value)
        pipe.expire(f"{day_key}:bandwidth", 86400 * 2)
    await pipe.execute()


async def check_quota(
    db: AsyncSession,
    redis_client: Redis,
    user_id: uuid.UUID,
) -> dict:
    """
    Check if user is within their plan limits.
    Returns {"allowed": True/False, "reason": "...", "current": {...}, "limits": {...}}
    """
    plan = await get_or_create_user_plan(db, user_id)

    # Check if banned
    if plan.is_banned:
        if plan.banned_until and plan.banned_until > datetime.now(timezone.utc):
            return {
                "allowed": False,
                "reason": f"Account banned until {plan.banned_until.isoformat()}",
                "current": {},
                "limits": {},
            }
        else:
            # Unban — ban period has expired
            plan.is_banned = False
            plan.banned_until = None
            await db.flush()

    limits = PLAN_LIMITS.get(plan.plan, PLAN_LIMITS[PlanTier.FREE.value])
    now = datetime.now(timezone.utc)

    # Check rate limit (requests per minute)
    minute_key = f"usage:minute:{user_id}:{now.strftime('%Y%m%d%H%M')}"
    current_requests = await redis_client.get(f"{minute_key}:requests")
    current_requests = int(current_requests) if current_requests else 0

    if current_requests >= limits["max_requests_per_min"]:
        return {
            "allowed": False,
            "reason": f"Rate limit exceeded: {current_requests}/{limits['max_requests_per_min']} req/min",
            "current": {"requests_per_min": current_requests},
            "limits": limits,
        }

    # Check connections
    day_key = f"usage:day:{user_id}:{now.strftime('%Y%m%d')}"
    current_connections = await redis_client.get(f"{day_key}:connections")
    current_connections = int(current_connections) if current_connections else 0

    if current_connections > limits["max_connections"]:
        return {
            "allowed": False,
            "reason": f"Connection limit exceeded: {current_connections}/{limits['max_connections']}",
            "current": {"connections": current_connections},
            "limits": limits,
        }

    # Check bandwidth
    current_bandwidth = await redis_client.get(f"{day_key}:bandwidth")
    current_bandwidth = int(current_bandwidth) if current_bandwidth else 0
    max_bandwidth_bytes = limits["max_bandwidth_per_day_gb"] * 1024 * 1024 * 1024

    if current_bandwidth >= max_bandwidth_bytes:
        return {
            "allowed": False,
            "reason": f"Bandwidth limit exceeded: {current_bandwidth}/{max_bandwidth_bytes} bytes",
            "current": {"bandwidth_today_bytes": current_bandwidth},
            "limits": limits,
        }

    return {
        "allowed": True,
        "reason": "ok",
        "current": {
            "requests_per_min": current_requests,
            "connections": current_connections,
            "bandwidth_today_bytes": current_bandwidth,
        },
        "limits": limits,
    }


async def ban_user(
    db: AsyncSession,
    redis_client: Redis,
    user_id: uuid.UUID,
    reason: str = "abuse",
):
    """Ban a user for abuse."""
    plan = await get_or_create_user_plan(db, user_id)
    plan.is_banned = True
    plan.banned_until = datetime.now(timezone.utc) + timedelta(
        hours=settings.ABUSE_BAN_DURATION_HOURS
    )
    await db.flush()
    # Log to Redis for fast checking
    await redis_client.setex(
        f"banned:{user_id}",
        settings.ABUSE_BAN_DURATION_HOURS * 3600,
        reason,
    )


async def unban_user(
    db: AsyncSession,
    redis_client: Redis,
    user_id: uuid.UUID,
):
    """Remove a ban from a user."""
    plan = await get_or_create_user_plan(db, user_id)
    plan.is_banned = False
    plan.banned_until = None
    await db.flush()
    await redis_client.delete(f"banned:{user_id}")


async def ban_ip(redis_client: Redis, ip: str, reason: str = "abuse"):
    """Ban an IP address."""
    await redis_client.setex(
        f"banned_ip:{ip}",
        settings.ABUSE_BAN_DURATION_HOURS * 3600,
        reason,
    )


async def get_usage_summary(
    db: AsyncSession,
    user_id: uuid.UUID,
    start: datetime,
    end: datetime,
) -> dict:
    """Get usage summary for a time period."""
    result = await db.execute(
        select(
            UsageRecord.metric_type,
            func.sum(UsageRecord.value).label("total"),
            func.count().label("count"),
        )
        .where(
            UsageRecord.user_id == user_id,
            UsageRecord.timestamp >= start,
            UsageRecord.timestamp <= end,
        )
        .group_by(UsageRecord.metric_type)
    )
    rows = result.all()
    summary = {
        "user_id": str(user_id),
        "period_start": start.isoformat(),
        "period_end": end.isoformat(),
        "metrics": {},
    }
    for row in rows:
        summary["metrics"][row.metric_type] = {
            "total": row.total,
            "count": row.count,
        }
    return summary


async def reset_user_usage(redis_client: Redis, user_id: uuid.UUID):
    """Reset all Redis counters for a user (admin action)."""
    pattern = f"usage:*:{user_id}:*"
    cursor = 0
    while True:
        cursor, keys = await redis_client.scan(cursor, match=pattern, count=100)
        if keys:
            await redis_client.delete(*keys)
        if cursor == 0:
            break


async def change_user_plan(
    db: AsyncSession,
    user_id: uuid.UUID,
    plan: str,
) -> UserPlan:
    """Change a user's plan and update limits accordingly."""
    user_plan = await get_or_create_user_plan(db, user_id)
    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS[PlanTier.FREE.value])

    user_plan.plan = plan
    user_plan.max_requests_per_min = limits["max_requests_per_min"]
    user_plan.max_connections = limits["max_connections"]
    user_plan.max_bandwidth_per_day_bytes = (
        limits["max_bandwidth_per_day_gb"] * 1024 * 1024 * 1024
    )
    await db.flush()
    return user_plan
