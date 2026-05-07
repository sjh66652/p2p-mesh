"""
Billing service - traffic accounting, plan management, QoS enforcement.
"""

import uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_

from app.config import settings
from app.models.user import UserPlan
from app.models.traffic import TrafficLog, Subscription, Invoice


# ---- QoS / Rate Limiting ----

def apply_qos(user_plan: str) -> str:
    """
    Determine the bandwidth limit for a user based on their plan.
    Returns "unlimited" for pro/enterprise, or a speed string for free.
    """
    plan_map = {
        UserPlan.FREE: settings.FREE_PLAN_BANDWIDTH_MBPS,
        UserPlan.PRO: settings.PRO_PLAN_BANDWIDTH_MBPS,
        UserPlan.ENTERPRISE: settings.ENTERPRISE_PLAN_BANDWIDTH_MBPS,
    }
    limit = plan_map.get(user_plan, settings.FREE_PLAN_BANDWIDTH_MBPS)
    if limit <= 0:
        return "unlimited"
    return f"{limit}MB/s"


# ---- Traffic Reporting ----

async def report_traffic(
    db: AsyncSession,
    user_id: uuid.UUID,
    device_id: uuid.UUID,
    peer_device_id: uuid.UUID | None,
    bytes_sent: int,
    bytes_received: int,
    connection_type: str = "p2p",
    relay_node_id: uuid.UUID | None = None,
    session_start: datetime | None = None,
    session_end: datetime | None = None,
) -> TrafficLog:
    """Record a traffic usage log entry."""
    now = datetime.now(timezone.utc)

    log = TrafficLog(
        user_id=user_id,
        device_id=device_id,
        peer_device_id=peer_device_id,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        connection_type=connection_type,
        relay_node_id=relay_node_id,
        session_start=session_start or now,
        session_end=session_end or now,
        timestamp=now,
    )
    db.add(log)
    await db.flush()
    await db.refresh(log)
    return log


async def get_user_traffic_summary(
    db: AsyncSession,
    user_id: uuid.UUID,
    period_start: datetime | None = None,
    period_end: datetime | None = None,
) -> dict:
    """Get aggregated traffic statistics for a user over a time period."""
    now = datetime.now(timezone.utc)
    if period_start is None:
        period_start = now - timedelta(days=30)
    if period_end is None:
        period_end = now

    # Total traffic
    total_result = await db.execute(
        select(
            func.coalesce(func.sum(TrafficLog.bytes_sent), 0),
            func.coalesce(func.sum(TrafficLog.bytes_received), 0),
        ).where(
            and_(
                TrafficLog.user_id == user_id,
                TrafficLog.timestamp >= period_start,
                TrafficLog.timestamp <= period_end,
            )
        )
    )
    total_sent, total_received = total_result.one()

    # P2P traffic
    p2p_result = await db.execute(
        select(
            func.coalesce(func.sum(TrafficLog.bytes_sent), 0),
            func.coalesce(func.sum(TrafficLog.bytes_received), 0),
        ).where(
            and_(
                TrafficLog.user_id == user_id,
                TrafficLog.connection_type == "p2p",
                TrafficLog.timestamp >= period_start,
                TrafficLog.timestamp <= period_end,
            )
        )
    )
    p2p_sent, p2p_received = p2p_result.one()

    # Relay traffic
    relay_result = await db.execute(
        select(
            func.coalesce(func.sum(TrafficLog.bytes_sent), 0),
            func.coalesce(func.sum(TrafficLog.bytes_received), 0),
        ).where(
            and_(
                TrafficLog.user_id == user_id,
                TrafficLog.connection_type == "relay",
                TrafficLog.timestamp >= period_start,
                TrafficLog.timestamp <= period_end,
            )
        )
    )
    relay_sent, relay_received = relay_result.one()

    return {
        "total_bytes_sent": int(total_sent or 0),
        "total_bytes_received": int(total_received or 0),
        "p2p_bytes": int((p2p_sent or 0) + (p2p_received or 0)),
        "relay_bytes": int((relay_sent or 0) + (relay_received or 0)),
        "period_start": period_start,
        "period_end": period_end,
    }


# ---- Subscription Management ----

PLAN_PRICES = {
    "free": 0,
    "pro": 999,     # $9.99/month (in cents)
    "enterprise": 4999,  # $49.99/month (in cents)
}


async def create_subscription(
    db: AsyncSession,
    user_id: uuid.UUID,
    plan: str,
    payment_method: str | None = None,
) -> Subscription:
    """Create a new subscription for a user."""
    if plan not in PLAN_PRICES:
        raise ValueError(f"Invalid plan: {plan}")

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=30) if plan != "free" else None

    sub = Subscription(
        user_id=user_id,
        plan=plan,
        status="active",
        started_at=now,
        expires_at=expires_at,
        auto_renew=True,
        payment_method=payment_method,
    )
    db.add(sub)
    await db.flush()

    # Generate first invoice
    if plan != "free":
        invoice = Invoice(
            user_id=user_id,
            subscription_id=sub.id,
            amount_cents=PLAN_PRICES[plan],
            currency="USD",
            status="pending",
            billing_period_start=now,
            billing_period_end=expires_at,
        )
        db.add(invoice)

    await db.flush()
    await db.refresh(sub)
    return sub


async def get_user_subscriptions(
    db: AsyncSession, user_id: uuid.UUID
) -> list[Subscription]:
    """Get all subscriptions for a user."""
    result = await db.execute(
        select(Subscription)
        .where(Subscription.user_id == user_id)
        .order_by(Subscription.started_at.desc())
    )
    return list(result.scalars().all())


async def cancel_subscription(
    db: AsyncSession, user_id: uuid.UUID, subscription_id: uuid.UUID
) -> Subscription:
    """Cancel an active subscription."""
    result = await db.execute(
        select(Subscription).where(
            Subscription.id == subscription_id,
            Subscription.user_id == user_id,
        )
    )
    sub = result.scalar_one_or_none()
    if not sub:
        raise ValueError("Subscription not found")

    sub.status = "canceled"
    sub.auto_renew = False
    await db.flush()
    await db.refresh(sub)
    return sub


async def get_user_invoices(
    db: AsyncSession, user_id: uuid.UUID
) -> list[Invoice]:
    """Get all invoices for a user."""
    result = await db.execute(
        select(Invoice)
        .where(Invoice.user_id == user_id)
        .order_by(Invoice.created_at.desc())
    )
    return list(result.scalars().all())
