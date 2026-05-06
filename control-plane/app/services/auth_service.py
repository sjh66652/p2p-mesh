"""
Authentication service - JWT, password hashing, brute-force protection.
"""

import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
from jose import jwt, JWTError
import secrets
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.config import settings
from app.models.user import User, UserPlan, UserRole
from app.schemas.user import UserRegister, UserLogin


# -- Password hashing with constant-time comparison --

def hash_password(password: str) -> str:
    """Hash a password using bcrypt (work factor 12)."""
    return bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(rounds=12)
    ).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its bcrypt hash (constant-time)."""
    return bcrypt.checkpw(
        password.encode("utf-8"), password_hash.encode("utf-8")
    )


# -- JWT with jti (JWT ID) for precise revocation --

def create_access_token(user_id: uuid.UUID, role: str = "user") -> dict:
    """Create a short-lived JWT access token with jti for revocation."""
    now = datetime.now(timezone.utc)
    jti = secrets.token_hex(16)  # Unique token ID

    payload = {
        "sub": str(user_id),
        "role": role,
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


def create_refresh_token(user_id: uuid.UUID) -> str:
    """Create a long-lived refresh token stored in Redis."""
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


# -- Registration with password validation --

def _validate_password_strength(password: str):
    """Enforce password complexity requirements."""
    if len(password) < 10:
        raise ValueError("Password must be at least 10 characters")
    if len(password) > 128:
        raise ValueError("Password must be at most 128 characters")
    # Check for at least 3 of: uppercase, lowercase, digit, special
    categories = sum([
        any(c.isupper() for c in password),
        any(c.islower() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])
    if categories < 3:
        raise ValueError(
            "Password must contain at least 3 of: uppercase, lowercase, digit, special character"
        )


async def register_user(db: AsyncSession, data: UserRegister) -> User:
    """Register a new user with password strength validation."""
    _validate_password_strength(data.password)

    existing = await db.execute(select(User).where(User.email == data.email))
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


# -- Login with brute-force protection --

async def login_user(
    db: AsyncSession, data: UserLogin, redis_client=None
) -> dict:
    """
    Authenticate a user. Enforces brute-force lockout via Redis.
    After LOGIN_MAX_ATTEMPTS failures, account is locked for LOGIN_LOCKOUT_MINUTES.
    """
    lockout_key = f"login_lockout:{data.email}"

    # Check lockout
    if redis_client:
        attempts = await redis_client.get(lockout_key)
        if attempts and int(attempts) >= settings.LOGIN_MAX_ATTEMPTS:
            ttl = await redis_client.ttl(lockout_key)
            raise ValueError(
                f"Account locked due to too many failed attempts. Try again in {ttl // 60 + 1} minutes."
            )

    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(data.password, user.password_hash):
        # Record failed attempt
        if redis_client:
            pipe = redis_client.pipeline()
            pipe.incr(lockout_key)
            pipe.expire(lockout_key, settings.LOGIN_LOCKOUT_MINUTES * 60)
            await pipe.execute()
        raise ValueError("Invalid email or password")

    if not user.is_active:
        raise ValueError("Account is disabled")

    # Clear lockout on success
    if redis_client:
        await redis_client.delete(lockout_key)

    # Create tokens
    token_data = create_access_token(user.id, role=user.role.value)
    refresh_token = create_refresh_token(user.id)

    # Store refresh token in Redis for revocation
    if redis_client:
        await redis_client.setex(
            f"refresh_token:{user.id}",
            settings.JWT_REFRESH_EXPIRE_DAYS * 86400,
            refresh_token,
        )

    token_data["refresh_token"] = refresh_token
    return token_data


async def refresh_access_token(refresh_token_str: str, redis_client) -> dict:
    """Issue a new access token using a valid refresh token."""
    try:
        payload = jwt.decode(
            refresh_token_str, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM]
        )
    except JWTError:
        raise ValueError("Invalid or expired refresh token")

    if payload.get("type") != "refresh":
        raise ValueError("Not a refresh token")

    user_id = uuid.UUID(payload["sub"])

    # Verify stored in Redis (not revoked)
    stored = await redis_client.get(f"refresh_token:{user_id}")
    if stored != refresh_token_str:
        raise ValueError("Refresh token has been revoked")

    return create_access_token(user_id, role=payload.get("role", "user"))


# -- Update with field whitelist (prevents role/plan escalation) --

ALLOWED_UPDATE_FIELDS = {"name"}

async def update_user(db: AsyncSession, user: User, data: dict) -> User:
    """
    Update user profile. ONLY whitelisted fields can be modified.
    This prevents attackers from changing plan/role/password via this endpoint.
    """
    for key, value in data.items():
        if value is not None and key in ALLOWED_UPDATE_FIELDS and hasattr(user, key):
            setattr(user, key, value)
    await db.flush()
    await db.refresh(user)
    return user


async def change_password(
    db: AsyncSession, user: User, old_password: str, new_password: str
):
    """Change password with strength validation and old-password verification."""
    _validate_password_strength(new_password)

    if not verify_password(old_password, user.password_hash):
        raise ValueError("Current password is incorrect")

    user.password_hash = hash_password(new_password)
    await db.flush()


async def logout_user(redis_client, token: str):
    """
    Blacklist a JWT access token. Also revoke the user's refresh token.
    """
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_exp": False},  # Allow expired tokens for logout
        )
        jti = payload.get("jti", "")
        user_id = payload.get("sub", "")
        exp = payload.get("exp", 0)
        now = datetime.now(timezone.utc).timestamp()
        ttl = max(int(exp - now), 1)

        # Blacklist access token by jti
        if jti:
            await redis_client.setex(f"jwt_blacklist:{jti}", ttl, "1")
        # Revoke refresh token
        if user_id:
            await redis_client.delete(f"refresh_token:{user_id}")
    except JWTError:
        pass  # Token already invalid, nothing to do


async def get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()
