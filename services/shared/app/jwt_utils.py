"""
JWT utilities shared across microservices.
Token creation, decoding, and verification for service-to-service auth.
"""

import uuid
import secrets
import logging
from datetime import datetime, timedelta, timezone

from jose import jwt, JWTError, ExpiredSignatureError

from shared.app.config import BaseConfig

logger = logging.getLogger("jwt_utils")


# Use a module-level settings placeholder; the calling service should
# import its own config and pass settings explicitly. For convenience,
# we provide a lazy-loaded BaseConfig so shared code works without crashing
# when DATABASE_URL is not set at import time.
_settings = None

def _get_settings():
    global _settings
    if _settings is None:
        _settings = BaseConfig()
    return _settings


def create_access_token(
    user_id: uuid.UUID,
    role: str = "user",
    plan: str = "FREE",
    settings=None,
) -> dict:
    """
    Create a short-lived JWT access token with jti for revocation.
    Includes the user's plan in the payload for downstream service decisions.
    """
    if settings is None:
        settings = _get_settings()

    now = datetime.now(timezone.utc)
    jti = secrets.token_hex(16)

    payload = {
        "sub": str(user_id),
        "role": role,
        "plan": plan,
        "jti": jti,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.JWT_ACCESS_EXPIRE_MINUTES),
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": settings.JWT_ACCESS_EXPIRE_MINUTES * 60,
    }


def create_refresh_token(user_id: uuid.UUID, settings=None) -> str:
    """
    Create a long-lived refresh token stored in Redis.
    """
    if settings is None:
        settings = _get_settings()

    now = datetime.now(timezone.utc)
    jti = secrets.token_hex(16)

    payload = {
        "sub": str(user_id),
        "jti": jti,
        "type": "refresh",
        "iat": now,
        "exp": now + timedelta(days=settings.JWT_REFRESH_EXPIRE_DAYS),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str, expected_type: str = "access", settings=None) -> dict:
    """
    Decode and validate a JWT token. Checks token type matches expected_type.
    Returns the decoded payload on success, raises ValueError on failure.
    """
    if settings is None:
        settings = _get_settings()

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "jti", "sub", "type"]},
        )
    except ExpiredSignatureError:
        logger.warning("Token decode failed: expired signature")
        raise ValueError("Token has expired")
    except JWTError as e:
        logger.warning("Token decode failed: %s", e)
        raise ValueError(f"Invalid token: {e}")

    if payload.get("type") != expected_type:
        logger.warning("Token type mismatch: expected %s, got %s", expected_type, payload.get("type"))
        raise ValueError(f"Token is not a {expected_type} token")

    return payload


def verify_service_token(token: str, settings=None) -> dict:
    """
    Verify an internal service-to-service token.
    Used by the API Gateway to pass authenticated identity to downstream services.
    These tokens have type="service" and carry user context without re-authentication.
    Returns the decoded payload or raises ValueError.
    """
    if settings is None:
        settings = _get_settings()

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "jti", "sub", "type"]},
        )
    except ExpiredSignatureError:
        logger.warning("Service token decode failed: expired signature")
        raise ValueError("Service token has expired")
    except JWTError as e:
        logger.warning("Service token decode failed: %s", e)
        raise ValueError(f"Invalid service token: {e}")

    if payload.get("type") not in ("service", "access"):
        raise ValueError("Invalid service token type")

    return payload
