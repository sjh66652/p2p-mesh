"""
Database connection and session management.
PostgreSQL via SQLAlchemy (async) + Redis for caching/signaling.
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
import redis.asyncio as aioredis

from shared.app.config import BaseConfig


# Default settings -- each service can pass its own config.
_settings = BaseConfig()


def init_engine(settings=None):
    """Create SQLAlchemy async engine from settings."""
    if settings is None:
        settings = _settings

    engine = create_async_engine(
        settings.DATABASE_URL,
        echo=settings.DEBUG,
        pool_size=20,
        max_overflow=10,
        pool_pre_ping=True,
    )
    return engine


# Default engine for module-level use
engine = init_engine()

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# Import the canonical Base from models_base to avoid dual-registry.
# All models must inherit from the SAME Base otherwise create_all misses them.
from shared.app.models_base import Base


async def get_db():
    """FastAPI dependency: yields an async database session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ---- Redis Connection ----
redis_client: aioredis.Redis | None = None


async def init_redis(settings=None):
    """Initialize Redis connection pool."""
    if settings is None:
        settings = _settings
    global redis_client
    redis_client = aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
    )
    await redis_client.ping()


async def close_redis():
    """Close Redis connection."""
    global redis_client
    if redis_client:
        await redis_client.close()


async def get_redis() -> aioredis.Redis:
    """FastAPI dependency: yields Redis client."""
    if redis_client is None:
        await init_redis()
    return redis_client
