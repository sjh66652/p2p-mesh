"""
Audit logging for security events.
Records user actions for compliance and forensic analysis.
"""

import json
import logging
import os
from datetime import datetime, timezone

import redis.asyncio as redis

logger = logging.getLogger("audit")

AUDIT_QUEUE = "queue:logs"

# Module-level connection pool
_redis_pool = None


async def _get_redis(redis_url: str = None):
    """Get a Redis connection from the module-level pool."""
    global _redis_pool
    if not redis_url:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    if _redis_pool is None:
        _redis_pool = redis.ConnectionPool.from_url(redis_url, decode_responses=True)
    return redis.Redis(connection_pool=_redis_pool)


async def close_audit_redis():
    """Close the module-level Redis connection pool."""
    global _redis_pool
    if _redis_pool is not None:
        await _redis_pool.disconnect()
        _redis_pool = None


async def audit_log(
    user_id: str = "anonymous",
    action: str = "",
    ip: str = "",
    details: dict = None,
    redis_url: str = None,
):
    """Record an audit event. Sends to Redis queue for async processing."""
    if not redis_url:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    event = {
        "user_id": user_id,
        "action": action,
        "ip": ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": details or {},
    }

    # Log locally
    logger.info("AUDIT: %s", json.dumps(event))

    # Queue for persistent storage (using connection pool)
    try:
        r = await _get_redis(redis_url)
        await r.rpush(AUDIT_QUEUE, json.dumps(event))
    except Exception as e:
        logger.warning("Failed to queue 