"""
FastAPI dependencies for Usage Service.
JWT validation, internal service auth, and admin role checks.
"""

import uuid
import hmac
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError

from app.config import settings
from app.database import get_db, get_redis
from sqlalchemy.ext.asyncio import AsyncSession
from redis.asyncio import Redis

security_scheme = HTTPBearer(auto_error=False)


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
    redis_client: Redis = Depends(get_redis),
):
    """
    Validate JWT access token. Checks:
    1. Signature and expiry (via pyjwt)
    2. Token type is 'access' (not a refresh token)
    3. jti is not blacklisted (precise revocation)
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

    if payload.get("type") != "access":
        raise credentials_exception

    user_id_str = payload.get("sub")
    jti = payload.get("jti")
    if not user_id_str or not jti:
        raise credentials_exception

    # Check blacklist by jti
    is_blacklisted = await redis_client.exists(f"jwt_blacklist:{jti}")
    if is_blacklisted:
        raise credentials_exception

    # Return minimal user info from token
    return {
        "id": uuid.UUID(user_id_str),
        "role": payload.get("role", "user"),
    }


async def verify_internal_service(request: Request):
    """
    Verify that the caller is another internal microservice.
    Uses X-Internal-API-Key header with constant-time comparison.
    """
    api_key = request.headers.get("X-Internal-API-Key", "")
    if not api_key or not _constant_time_compare(api_key, settings.INTERNAL_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid internal API key",
        )
    return True


async def require_admin(user=Depends(get_current_user)):
    """Require admin role."""
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user
