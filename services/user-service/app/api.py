"""
User and Device API routes.
Prefix: /api/users
"""

import uuid
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import Response

from app.database import get_db, get_redis
from app.dependencies import get_current_user, verify_internal_service
from app.schemas import (
    UserResponse, DeviceResponse, DeviceRegister,
    DeviceHeartbeat, DeviceListResponse, UserUpdate,
)
from app import service as user_service
from shared.app.usage_middleware import check_usage_quota

router = APIRouter(dependencies=[Depends(check_usage_quota)])


@router.get("/", response_model=list[UserResponse])
async def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all users (admin only)."""
    if user.role.value != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    users = await user_service.list_users(db, skip=skip, limit=limit)
    return users


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: uuid.UUID,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a user's profile. Users can only access their own profile."""
    if user.id != user_id and user.role.value != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )
    target = await user_service.get_user_by_id(db, user_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return target


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    data: UserUpdate,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a user's profile. Users can only update their own profile."""
    if user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )
    try:
        updated = await user_service.update_user(
            db, user, data.model_dump(exclude_unset=True)
        )
        return updated
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/{user_id}/devices", response_model=DeviceListResponse)
async def list_devices(
    user_id: uuid.UUID,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all devices for a user."""
    if user.id != user_id and user.role.value != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )
    devices = await user_service.get_user_devices(db, user_id)
    return DeviceListResponse(devices=devices, total=len(devices))


@router.post("/{user_id}/devices", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
async def register_device(
    user_id: uuid.UUID,
    data: DeviceRegister,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Register a new device for a user."""
    if user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )
    try:
        device = await user_service.register_device(db, user_id, data)
        return device
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/{user_id}/devices/{device_id}", response_model=DeviceResponse)
async def get_device(
    user_id: uuid.UUID,
    device_id: uuid.UUID,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific device for a user."""
    if user.id != user_id and user.role.value != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )
    device = await user_service.get_device_by_id(db, device_id, user_id=user_id)
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )
    return device


@router.post("/{user_id}/devices/{device_id}/heartbeat", response_model=DeviceResponse)
async def device_heartbeat(
    user_id: uuid.UUID,
    device_id: uuid.UUID,
    data: DeviceHeartbeat,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update device heartbeat and network information."""
    if user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )
    device = await user_service.get_device_by_id(db, device_id, user_id=user_id)
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )
    updated = await user_service.update_device_heartbeat(db, device, data)
    return updated


@router.delete("/{user_id}/devices/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
    user_id: uuid.UUID,
    device_id: uuid.UUID,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a device."""
    if user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )
    device = await user_service.get_device_by_id(db, device_id, user_id=user_id)
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )
    await user_service.delete_device(db, device)

