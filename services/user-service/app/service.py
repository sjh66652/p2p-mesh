"""
User and device management service.
Handles CRUD operations for user profiles and devices.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from shared.app.models_base import User, Device
from app.schemas import DeviceRegister, DeviceHeartbeat


# -- User services --

async def get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    """Fetch a user by their UUID."""
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


ALLOWED_UPDATE_FIELDS = {"name"}


async def update_user(db: AsyncSession, user: User, data: dict) -> User:
    """
    Update user profile. ONLY whitelisted fields can be modified.
    Prevents attackers from changing plan/role/etc. via this endpoint.
    """
    for key, value in data.items():
        if value is not None and key in ALLOWED_UPDATE_FIELDS and hasattr(user, key):
            setattr(user, key, value)
    await db.flush()
    await db.refresh(user)
    return user


async def list_users(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 100,
) -> list[User]:
    """List users with pagination (admin only)."""
    result = await db.execute(
        select(User).offset(skip).limit(limit)
    )
    return list(result.scalars().all())


# -- Device services --

async def get_user_devices(db: AsyncSession, user_id: uuid.UUID) -> list[Device]:
    """List all devices for a given user."""
    result = await db.execute(
        select(Device).where(Device.user_id == user_id)
    )
    return list(result.scalars().all())


async def register_device(
    db: AsyncSession,
    user_id: uuid.UUID,
    data: DeviceRegister,
) -> Device:
    """Register a new device for a user.
    Checks for duplicate public keys to prevent key reuse."""
    # Check for duplicate public key
    existing = await db.execute(
        select(Device).where(Device.public_key == data.public_key)
    )
    if existing.scalar_one_or_none():
        raise ValueError("Device with this public key already exists")

    device = Device(
        user_id=user_id,
        name=data.name,
        public_key=data.public_key,
        os=data.os,
        version=data.version,
    )
    db.add(device)
    await db.flush()
    await db.refresh(device)
    return device


async def get_device_by_id(
    db: AsyncSession,
    device_id: uuid.UUID,
    user_id: uuid.UUID | None = None,
) -> Device | None:
    """Get a device by ID. Optionally scope to a specific user."""
    query = select(Device).where(Device.id == device_id)
    if user_id is not None:
        query = query.where(Device.user_id == user_id)
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def update_device_heartbeat(
    db: AsyncSession,
    device: Device,
    heartbeat: DeviceHeartbeat,
) -> Device:
    """Update device heartbeat timing and network info."""
    device.last_seen = datetime.now(timezone.utc)
    device.online = True
    if heartbeat.nat_type is not None:
        device.nat_type = heartbeat.nat_type
    if heartbeat.last_ip is not None:
        device.last_ip = heartbeat.last_ip
    if heartbeat.last_port is not None:
        device.last_port = heartbeat.last_port
    await db.flush()
    await db.refresh(device)
    return device


async def delete_device(db: AsyncSession, device: Device):
    """Delete a device from the database."""
    await db.delete(device)
    await db.flush()
