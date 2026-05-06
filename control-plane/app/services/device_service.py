"""
Device management service - registration, heartbeats, online/offline tracking.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.device import Device, NATType
from app.schemas.device import DeviceRegister, DeviceHeartbeat


async def register_device(
    db: AsyncSession, user_id: uuid.UUID, data: DeviceRegister
) -> Device:
    """Register a new device under a user's account."""
    # Check for duplicate public key
    existing = await db.execute(
        select(Device).where(Device.public_key == data.public_key)
    )
    if existing.scalar_one_or_none():
        raise ValueError("A device with this public key already exists")

    device = Device(
        user_id=user_id,
        name=data.name,
        public_key=data.public_key,
        os=data.os,
        version=data.version,
        online=False,
    )
    db.add(device)
    await db.flush()
    await db.refresh(device)
    return device


async def get_user_devices(
    db: AsyncSession, user_id: uuid.UUID
) -> list[Device]:
    """Get all devices belonging to a user."""
    result = await db.execute(
        select(Device)
        .where(Device.user_id == user_id)
        .order_by(Device.last_seen.desc())
    )
    return list(result.scalars().all())


async def get_device_by_id(
    db: AsyncSession, device_id: uuid.UUID
) -> Device | None:
    """Get a device by its ID."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    return result.scalar_one_or_none()


async def update_heartbeat(
    db: AsyncSession, device_id: uuid.UUID, data: DeviceHeartbeat
) -> Device:
    """Update the heartbeat / status of a device."""
    device = await get_device_by_id(db, device_id)
    if not device:
        raise ValueError("Device not found")

    now = datetime.now(timezone.utc)

    if data.nat_type is not None:
        device.nat_type = data.nat_type
    if data.last_ip is not None:
        device.last_ip = data.last_ip
    if data.last_port is not None:
        device.last_port = data.last_port

    device.online = True
    device.last_seen = now
    await db.flush()
    await db.refresh(device)
    return device


async def set_device_offline(
    db: AsyncSession, device_id: uuid.UUID
) -> Device:
    """Mark a device as offline."""
    device = await get_device_by_id(db, device_id)
    if not device:
        raise ValueError("Device not found")

    device.online = False
    device.last_seen = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(device)
    return device


async def delete_device(
    db: AsyncSession, user_id: uuid.UUID, device_id: uuid.UUID
) -> bool:
    """Remove a device from the user's account."""
    device = await get_device_by_id(db, device_id)
    if not device or device.user_id != user_id:
        raise ValueError("Device not found or does not belong to user")

    await db.delete(device)
    await db.flush()
    return True


async def count_online_devices(db: AsyncSession) -> int:
    """Count how many devices are currently online."""
    result = await db.execute(
        select(func.count()).select_from(Device).where(Device.online == True)
    )
    return result.scalar_one()
