"""
Authentication service - JWT token creation, password hashing, user management.
"""

import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.config import settings
from app.models.user import User, UserPlan, UserRole
from app.schemas.user import UserRegister, UserLogin


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its bcrypt hash."""
    return bcrypt.checkpw(
        password.encode("utf-8"), password_hash.encode("utf-8")
    )


def create_jwt(user_id: uuid.UUID, role: str = "user") -> dict:
    """Create a JWT access token and return it with metadata."""
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)

    payload = {
        "sub": str(user_id),
        "role": role,
        "iat": now,
        "exp": expires_at,
    }
    token = jwt.encode(
        payload,
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": settings.JWT_EXPIRE_MINUTES * 60,
    }


async def register_user(db: AsyncSession, data: UserRegister) -> User:
    """Register a new user."""
    # Check if email already exists
    existing = await db.execute(
        select(User).where(User.email == data.email)
    )
    if existing.scalar_one_or_none():
        raise ValueError("Email already registered")

    user = User(
        email=data.email,
        password_hash=hash_password(data.password),
        name=data.name,
        plan=UserPlan.FREE,
        role=UserRole.USER,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


async def login_user(db: AsyncSession, data: UserLogin) -> dict:
    """Authenticate a user and return a JWT token."""
    result = await db.execute(
        select(User).where(User.email == data.email)
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(data.password, user.password_hash):
        raise ValueError("Invalid email or password")

    if not user.is_active:
        raise ValueError("Account is disabled")

    return create_jwt(user.id, role=user.role.value)


async def get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    """Get a user by their ID."""
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def update_user(db: AsyncSession, user: User, data: dict) -> User:
    """Update user profile fields."""
    for key, value in data.items():
        if value is not None and hasattr(user, key):
            setattr(user, key, value)
    await db.flush()
    await db.refresh(user)
    return user


async def change_password(
    db: AsyncSession, user: User, old_password: str, new_password: str
):
    """Change user's password after verifying the old one."""
    if not verify_password(old_password, user.password_hash):
        raise ValueError("Current password is incorrect")
    user.password_hash = hash_password(new_password)
    await db.flush()


async def logout_user(redis_client, token: str):
    """Blacklist a JWT token so it can no longer be used."""
    from app.config import settings
    ttl = settings.JWT_EXPIRE_MINUTES * 60
    await redis_client.setex(f"jwt_blacklist:{token}", ttl, "1")
