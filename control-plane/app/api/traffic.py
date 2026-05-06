"""Traffic reporting API routes - usage data from Rust data nodes."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.schemas.traffic import TrafficReport, TrafficReportBatch, TrafficSummary
from app.services import billing_service

router = APIRouter()


@router.post("/report", status_code=status.HTTP_201_CREATED)
async def report_traffic(
    data: TrafficReport,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Report traffic usage from a data node (single session)."""
    log = await billing_service.report_traffic(
        db,
        user_id=user.id,
        device_id=data.device_id,
        peer_device_id=data.peer_device_id,
        bytes_sent=data.bytes_sent,
        bytes_received=data.bytes_received,
        connection_type=data.connection_type,
        relay_node_id=data.relay_node_id,
        session_start=data.session_start,
        session_end=data.session_end,
    )
    return {
        "id": log.id,
        "status": "recorded",
        "timestamp": log.timestamp.isoformat(),
    }


@router.post("/report/batch", status_code=status.HTTP_201_CREATED)
async def report_traffic_batch(
    data: TrafficReportBatch,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Report a batch of traffic sessions for efficiency."""
    count = 0
    for report in data.reports:
        await billing_service.report_traffic(
            db,
            user_id=user.id,
            device_id=report.device_id,
            peer_device_id=report.peer_device_id,
            bytes_sent=report.bytes_sent,
            bytes_received=report.bytes_received,
            connection_type=report.connection_type,
            relay_node_id=report.relay_node_id,
            session_start=report.session_start,
            session_end=report.session_end,
        )
        count += 1

    return {"sessions_recorded": count}


@router.get("/summary")
async def get_traffic_summary(
    period_start: str | None = Query(None, description="ISO 8601 start date"),
    period_end: str | None = Query(None, description="ISO 8601 end date"),
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get traffic usage summary for the current user."""
    start = datetime.fromisoformat(period_start) if period_start else None
    end = datetime.fromisoformat(period_end) if period_end else None

    summary = await billing_service.get_user_traffic_summary(
        db, user.id, period_start=start, period_end=end
    )
    return summary


@router.get("/qos")
async def get_qos_policy(user=Depends(get_current_user)):
    """Get the QoS (bandwidth limit) policy for the current user."""
    limit = billing_service.apply_qos(user.plan.value)
    return {
        "user_id": str(user.id),
        "plan": user.plan.value,
        "bandwidth_limit": limit,
    }
