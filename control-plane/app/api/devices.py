"""Device management API routes."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.schemas.device import (
    DeviceRegister, DeviceHeartbeat,
    DeviceResponse, DeviceListResponse,
)
from app.services import device_service

router = APIRouter()


@router.post("", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
async def register_device(
    data: DeviceRegister,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Register a new device for the current user."""
    try:
        device = await device_service.register_device(db, user.id, data)
        return device
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.get("", response_model=DeviceListResponse)
async def list_devices(
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all devices belonging to the current user."""
    devices = await device_service.get_user_devices(db, user.id)
    return DeviceListResponse(
        devices=devices,
        total=len(devices),
    )


@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get details of a specific device."""
    from uuid import UUID
    device = await device_service.get_device_by_id(db, UUID(device_id))
    if not device or device.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )
    return device


@router.post("/{device_id}/heartbeat", response_model=DeviceResponse)
async def heartbeat(
    device_id,
    data: DeviceHeartbeat,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update device heartbeat to keep it marked as online."""
    from uuid import UUID
    device = await device_service.get_device_by_id(db, UUID(device_id))
    if not device or device.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )
    try:
        device = await device_service.update_heartbeat(db, UUID(device_id), data)
        return device
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
    device_id,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove a device from the user's account."""
    from uuid import UUID
    try:
        await device_service.delete_device(db, user.id, UUID(device_id))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
