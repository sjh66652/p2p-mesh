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

    # Queue for persistent storage
    try:
        r = redis.from_url(redis_url, decode_responses=True)
        await r.rpush(AUDIT_QUEUE, json.dumps(event))
        await r.close()
    except Exception as e:
        logger.warning("Failed to queue audit event: %s", e)


# Common audit actions
class AuditActions:
    USER_REGISTER = "user.register"
    USER_LOGIN = "user.login"
    USER_LOGIN_FAILED = "user.login.failed"
    USER_LOGOUT = "user.logout"
    USER_UPDATE = "user.update"
    USER_DELETE = "user.delete"
    DEVICE_REGISTER = "device.register"
    DEVICE_DELETE = "device.delete"
    WS_CONNECT = "ws.connect"
    WS_DISCONNECT = "ws.disconnect"
    RELAY_REGISTER = "relay.register"
    RELAY_HEARTBEAT = "relay.heartbeat"
    QUOTA_EXCEEDED = "quota.exceeded"
    USER_BANNED = "user.banned"
    PLAN_CHANGED = "plan.changed"
    ADMIN_ACTION = "admin.action"
