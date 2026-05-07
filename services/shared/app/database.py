"""
Database connection and session management.
PostgreSQL via SQLAlchemy (async) + Redis for caching/signaling.

Lazy initialization: engine is not created at import time, avoiding
crashes when DATABASE_URL is not set in environments that import shared
modules but don't need a database connection.
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
import redis.asyncio as aioredis

from shared.app.config import BaseConfig


# Default settings -- lazy-loaded to avoid crash on import without DATABASE_URL
_settings = None
_engine = None
_async_session_factory = None


def _get_settings():
    global _settings
    if _settings is None:
        _settings = BaseConfig()
    return _settings


def get_settings():
    """Get the shared settings instance (lazy)."""
    return _get_settings()


def init_engine(settings=None):
    """Create SQLAlchemy async engine from settings."""
    if settings is None:
        settings = _get_settings()

    return create_async_engine(
        settings.DATABASE_URL,
        echo=settings.DEBUG,
        pool_size=20,
        max_overflow=10,
        pool_pre_ping=True,
    )


def get_engine():
    """Get or create the shared async engine (lazy initialization)."""
    global _engine
    if _engine is None:
        _engine = init_engine()
    return _engine


def get_async_session_factory():
    """Get or create the shared async session factory (lazy initialization)."""
    global _async_session_factory
    if _async_session_factory is None:
        _async_session_factory = async_sessionmaker(
            get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _async_session_factory


# Backward-compatible lazy module-level attributes (Python 3.7+)
def __getattr__(name):
    if name == "engine":
        return get_engine()
    if name == "async_session_factory":
        return get_async_session_factory()
    raise AttributeError(f"module 'shared.app.database' has no attribute '{name}'")
