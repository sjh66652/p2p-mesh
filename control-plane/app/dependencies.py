"""
Shared FastAPI dependencies: authentication, authorization, and common helpers.
"""

import uuid
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from jwt.exceptions import InvalidTokenError

from app.config import settings
from app.database import get_db, get_redis

security_scheme = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db=Depends(get_db),
):
    """
    Validate JWT token and return the current authenticated user.
    Used as a dependency on protected endpoints.
    """
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception

    # Check token in Redis blacklist (for logout)
    redis = await get_redis()
    is_blacklisted = await redis.exists(f"jwt_blacklist:{token}")
    if is_blacklisted:
        raise credentials_exception

    # Fetch user from database
    from sqlalchemy import select
    from app.models.user import User

    result = await db.execute(
        select(User).where(User.id == uuid.UUID(user_id))
    )
    user = result.scalar_one_or_none()

    if user is None:
        raise credentials_exception

    return user


async def get_current_active_device(
    user=Depends(get_current_user),
    db=Depends(get_db),
):
    """
    Validate the user has at least one active device.
    Returns the user.
    """
    from sqlalchemy import select
    from app.models.device import Device

    result = await db.execute(
        select(Device).where(
            Device.user_id == user.id,
            Device.online == True,
        ).limit(1)
    )
    device = result.scalar_one_or_none()

    if device is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No active device found. Please register a device first.",
        )

    return user
