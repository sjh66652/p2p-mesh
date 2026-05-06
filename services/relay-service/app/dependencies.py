"""
FastAPI dependencies: relay auth, admin checks, JWT validation.

The relay-service does not own the user database. User authentication
is performed by validating the JWT token and checking claims directly,
without querying a User table. Admin role is determined from JWT claims.
"""

import uuid
import hmac
import logging

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError

from app.config import settings
from app.database import get_redis

logger = logging.getLogger(__name__)
security_scheme = HTTPBearer(auto_error=False)


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks.
    Uses hmac.compare_digest which is immune to timing side-channels."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


async def get_relay_auth(request: Request):
    """
    Authenticate relay nodes via a shared bearer token.
    Relays are not user accounts -- they use RELAY_AUTH_TOKEN for API access.
    Uses constant-time comparison to prevent timing side-channel attacks.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Relay authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header[7:]  # strip "Bearer "
    if not _constant_time_compare(token, settings.RELAY_AUTH_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid relay credentials",
        )

    return token


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
    redis_client=Depends(get_redis),
):
    """
    Validate JWT access token without requiring a User model.
    The relay-service does not own the user database; it validates
    the JWT and extracts user info from the token claims.

    Checks:
    1. Signature and expiry (via pyjwt)
    2. Token type is 'access' (not a refresh token)
    3. jti is not blacklisted (precise revocation)

    Returns a dict with user info or raises 401.
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

    # Validate user_id is a proper UUID
    try:
        user_uuid = uuid.UUID(user_id_str)
    except ValueError:
        raise credentials_exception

    # Return a minimal user dict with role from JWT claims
    role = payload.get("role", "user")
    return {
        "id": user_uuid,
        "sub": user_id_str,
        "role": role,
        "jti": jti,
    }


async def require_admin(user=Depends(get_current_user)):
    """Require admin role (from JWT claims)."""
    role = user.get("role", "")
    if role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user
