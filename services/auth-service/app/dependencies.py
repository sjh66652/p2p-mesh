"""
FastAPI dependencies: JWT auth, constant-time comparison, jti blacklist check.
Mirrors the original monolith's dependencies.py with all security fixes preserved.
"""

import uuid
import hmac

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from sqlalchemy import select

from app.config import settings
from app.database import get_db, get_redis
from shared.app.models_base import User

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
    try:
        user_uuid = uuid.UUID(user_id_str)
    except ValueError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_uuid))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise credentials_exception

    return user
