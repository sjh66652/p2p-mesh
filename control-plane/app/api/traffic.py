"""Traffic reporting API routes - with anti-fraud validation."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.config import settings
from app.database import get_db
from app.dependencies import get_current_user
from app.models.device import Device
from app.schemas.traffic import TrafficReport, TrafficReportBatch
from app.services import billing_service

router = APIRouter()


def _validate_traffic_report(data: TrafficReport):
    """Validate traffic data to prevent billing fraud."""
    # Cap per-report bytes to prevent overflow/inflation attacks
    max_bytes = settings.MAX_TRAFFIC_REPORT_BYTES
    if data.bytes_sent > max_bytes or data.bytes_received > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Traffic report exceeds maximum of {max_bytes} bytes",
        )
    # Validate connection_type
    if data.connection_type not in ("p2p", "relay"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="connection_type must be 'p2p' or 'relay'",
        )
    # Session time bounds
    if data.session_start and data.session_end:
        if data.session_start > data.session_end:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="session_start must be before session_end",
            )


@router.post("/report", status_code=status.HTTP_201_CREATED)
async def report_traffic(
    data: TrafficReport,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Report traffic usage from a data node. Validated for fraud prevention."""
    _validate_traffic_report(data)

    # Verify device belongs to user
    result = await db.execute(
        select(Device).where(Device.id == data.device_id, Device.user_id == user.id)
    )
    if not result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Device not found or does not belong to you",
        )

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
    return {"id": log.id, "status": "recorded"}


@router.post("/report/batch", status_code=status.HTTP_201_CREATED)
async def report_traffic_batch(
    data: TrafficReportBatch,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Report a batch of traffic sessions. Max 100 per batch."""
    if len(data.reports) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 100 reports per batch",
        )

    count = 0
    for report in data.reports:
        _validate_traffic_report(report)

        # Verify source device belongs to user
        result = await db.execute(
            select(Device).where(Device.id == report.device_id, Device.user_id == user.id)
        )
        if not result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Device {report.device_id} not found or does not belong to you",
            )

        # Verify peer device also belongs to the same user (prevents cross-user billing fraud)
        if report.peer_device_id:
            peer_result = await db.execute(
                select(Device).where(Device.id == report.peer_device_id, Device.user_id == user.id)
            )
            if not peer_result.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Peer device {report.peer_device_id} not found or does not belong to you",
                )

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
    period_start: str | None = Query(None),
    period_end: str | None = Query(None),
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get traffic usage summary for the current user."""
    start = datetime.fromisoformat(period_start) if period_start else None
    end = datetime.fromisoformat(period_end) if period_end else None