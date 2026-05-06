"""Authentication API routes - login, register, profile management."""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db, get_redis
from app.dependencies import get_current_user, security_scheme
from app.schemas.user import (
    UserRegister, UserLogin, TokenResponse,
    UserResponse, UserUpdate, PasswordChange,
)
from app.services import auth_service

router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(data: UserRegister, db: AsyncSession = Depends(get_db)):
    """Register a new user account."""
    try:
        user = await auth_service.register_user(db, data)
        return user
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.post("/login", response_model=TokenResponse)
async def login(data: UserLogin, db: AsyncSession = Depends(get_db)):
    """Authenticate and receive a JWT access token."""
    try:
        token_data = await auth_service.login_user(db, data)
        return token_data
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    redis_client=Depends(get_redis),
):
    """Invalidate the current JWT token."""
    await auth_service.logout_user(redis_client, credentials.credentials)


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
    """Update the current user's profile."""
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
    """Change the current user's password."""
    try:
        await auth_service.change_password(
            db, user, data.old_password, data.new_password
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
