"""
Authentication API routes - login, register, token refresh.
Prefix: /api/auth
"""

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


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    data: UserRegister,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Register a new user account."""
    try:
        user = await auth_service.register_user(db, data)
        client_ip = request.client.host if request.client else "unknown"
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
        await audit_log(data.email, AuditActions.USER_LOGIN_FAILED, client_ip)
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


@router.patch("/me", response_model=UserResponse)
async def update_profile(
    data: UserUpdate,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update user profile. Only whitelisted fields can be modified."""
    try:
        updated = await auth_service.update_user(
            db, user, data.model_dump(exclude_unset=True)
        )
        return updated
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    data: PasswordChange,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change password (requires current password)."""
    try:
        await auth_service.change_password(db, user, data.old_password, data.new_password)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

