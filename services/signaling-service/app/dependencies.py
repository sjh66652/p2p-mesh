"""
FastAPI dependencies: JWT auth for WebSocket, internal service verification.
"""

import uuid
import hmac
import logging

from fastapi import HTTPException, status, Request
from jose import jwt, JWTError

from app.config import settings

logger = logging.getLogger(__name__)


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks.
    Uses hmac.compare_digest which is immune to timing side-channels."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


async def get_current_user_from_token(
    request: Request,
) -> dict:
    """
    Extract and validate JWT from Authorization header.
    Returns the token payload including sub (user_id) and jti.
    Used by WebSocket connections (not FastAPI Depends with HTTPBearer,
    because WebSocket headers are accessed differently).

    Checks:
    1. Signature and expiry (via pyjwt)
    2. Token type is 'access' (not a refresh token)
    3. jti is present for blacklist checking
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    token = auth_header[7:]  # strip "Bearer "

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "sub", "type", "jti"]},
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    # Reject refresh tokens used as access tokens
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )

    user_id_str = payload.get("sub")
    jti = payload.get("jti")
    if not user_id_str or not jti:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    # Validate user_id is a proper UUID
    try:
        uuid.UUID(user_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    return payload


async def verify_internal_service(request: Request):
    """
    Verify internal service-to-service communication via X-Internal-API-Key header.
    Used between microservices (e.g., auth-service calling signaling-service).
    """
    api_key = request.headers.get("X-Internal-API-Key", "")
    if not api_key or not _constant_time_compare(api_key, settings.INTERNAL_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden",
        )
    return True
