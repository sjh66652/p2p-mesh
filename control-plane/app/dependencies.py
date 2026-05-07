"""
FastAPI dependencies: JWT auth, device ownership verification, role checks.
"""

import uuid

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError

import hmac

from app.config import settings
from app.database import get_db, get_redis

security_scheme = HTTPBearer(auto_error=False)


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks.
    Uses hmac.compare_digest which is immune to timing side-channels."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
    db=Depends(get_db),
    redis_client=Depends(get_redis),
):
    """
    Validate JWT access token. Checks:
    1. Signature and expiry (via pyjwt)
    2. Token type is 'access' (not a refresh token)
    3. jti is not blacklisted (precise revocation)
    4. User exists and is active

    Returns the authenticated User or raises 401.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
            headers={"WWW-Authenticate": "Bearer"},
        )

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
            options={"require": ["exp", "jti", "sub", "type"]},
        )
    except JWTError:
        raise credentials_exception

    # Reject refresh tokens used as access tokens
    if payload.get("type") != "access":
        raise credentials_exception

    user_id_str = payload.get("sub")
    jti = payload.get("jti")
    if not user_id_str or not jti:
        raise credentials_exception

    # Check blacklist by jti (precise revocation)
    is_blacklisted = await redis_client.exists(f"jwt_blacklist:{jti}")
    if is_blacklisted:
        raise credentials_exception

    # Fetch user
    from sqlalchemy import select
    from app.models.user import User

    try:
        user_uuid = uuid.UUID(user_id_str)
    except ValueError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_uuid))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise credentials_exception

    # Invalidate tokens issued before the user's last password change.
    # This ensures that changing passwords logs out all other sessions.
    token_iat = payload.get("iat")
    if token_iat is not None and user.password_updated_at is not None:
        # Compare as timestamps: if token was issued before the password change, reject it
        if token_iat < user.password_updated_at.timestamp():
            raise credentials_exception

    return user


async def get_current_device(
    device_id: str,
    user=Depends(get_current_user),
    db=Depends(get_db),
):
    """
    Verify that the given device_id belongs to the authenticated user.
    Used by WebSocket and device-specific endpoints to prevent
    cross-user device impersonation.
    """
    from sqlalchemy import select
    from app.models.device import Device

    try:
        dev_uuid = uuid.UUID(device_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid device_id")

    result = await db.execute(
        select(Device).where(Device.id == dev_uuid, Device.user_id == user.id)
    )
    device = result.scalar_one_or_none()

    if device is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Device not found or does not belong to you",
        )

    return device, user


async def require_admin(user=Depends(get_current_user)):
    """Require admin role."""
    if user.role.value != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user


async def get_relay_auth(request: Request):
    """
    Authenticate relay nodes via a shared bearer token.
    Relays are not user accounts — they use RELAY_AUTH_TOKEN for API access.
    """
    from app.config import settings

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Relay authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header[7:]  # strip "Bearer "
    # Constant-time comparison to prevent timing side-channel attacks
    if not _constant_time_compare(token, settings.RELAY_AUTH_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid relay credentials",
        )

    return token
