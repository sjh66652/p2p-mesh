"""
Authentication API routes - login, register, token refresh.
Prefix: /api/auth
"""

import hashlib

from fastapi import APIRouter, Depends, HTTPException, status, Body, Request
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import Response

from app.database import get_db, get_redis
from app.dependencies import get_current_user, security_scheme
from app.schemas import (
    UserRegister, UserLogin, TokenResponse,
    UserResponse, UserUpdate, PasswordChange, RefreshRequest,
)
from app import service as auth_service
from shared.app.usage_middleware import check_usage_quota
from shared.app.audit import audit_log, AuditActions

router = APIRouter(dependencies=[Depends(check_usage_quota)])


async def _check_registration_rate_limit(redis_client, client_ip: str):
    """Rate limit registrations per IP: max 5 per hour."""
    key = f"reg_rate_limit:{client_ip}"
    count = await redis_client.get(key)
    if count and int(count) >= 5:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts. Please try again later.",
        )
    pipe = redis_client.pipeline()
    pipe.incr(key)
    pipe.expire(key, 3600)
    await pipe.execute()


def hash_email(email: str) -> str:
    """Hash an email address for audit logging (prevents PII leakage)."""
    from app.config import settings
    return hashlib.sha256((email + settings.JWT_SECRET).encode()).hexdigest()[:16]


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    data: UserRegister,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis_client=Depends(get_redis),
):
    """Register a new user account."""
    client_ip = request.client.host if request.client else "unknown"

    # Rate limit registrations per IP
    if redis_client:
        await _check_registration_rate_limit(redis_client, client_ip)

    try:
        user = await auth_service.register_user(db, data)
        await audit_log(str(user.id), AuditActions.USER_REGISTER, client_ip)
        return user
    except ValueError as e:
        # Use generic error to prevent user enumeration
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration failed. Check your input and try again.",
        )


@router.post("/login")
async def login(
    data: UserLogin,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis_client=Depends(get_redis),
):
    """Authenticate and receive JWT tokens (access + refresh)."""
    client_ip = request.client.host if request.client else "unknown"
    try:
        token_data = await auth_service.login_user(db, data, redis_client)
        # Extract user_id from the access token for audit
        from jose import jwt
        from app.config import settings
        payload = jwt.decode(
            token_data["access_token"], settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_exp": False},
        )
        user_id = payload.get("sub", "unknown")
        await audit_log(user_id, AuditActions.USER_LOGIN, client_ip)
        return token_data
    except ValueError as e:
        await audit_log(hash_email(data.email), AuditActions.USER_LOGIN_FAILED, client_ip)
        # Generic error -- don't reveal whether email exists
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )


@router.post("/refresh")
async def refresh_token(
    data: RefreshRequest,
    redis_client=Depends(get_redis),
    db: AsyncSession = Depends(get_db),
):
    """Get a new access token using a refresh token."""
    try:
        token_data = await auth_service.refresh_access_token(
            data.refresh_token, redis_client, db=db
        )
        return token_data
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    request: Request = None,
    redis_client=Depends(get_redis),
):
    """Invalidate current tokens (access + refresh)."""
    client_ip = request.client.host if request and request.client else "unknown"
    # Extract user_id from token for audit before blacklisting
    from jose import jwt
    from app.config import settings
    try:
        payload = jwt.decode(
            credentials.credentials, settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_exp": False},
        )
        user_id = payload.get("sub", "unknown")
    except Exception:
        user_id = "unknown"

    await auth_service.logout_user(redis_client, credentials.credentials)
    await audit_log(user_id, AuditActions.USER_LOGOUT, client_ip)


@router.get("/me", response_model=UserResponse)
async def get_profile(user=Depends(get_current_user)):
    """Get the current authenticated user's profile."""
    return user


@router.patch("/me", response_model