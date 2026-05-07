"""
Rate limiting middleware using Redis-backed sliding window algorithm.
Production-safe across multiple API replicas. No memory leak.
"""

import time
import logging

from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware


logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Redis-backed rate limiting middleware.

    Each instance shares the same Redis, so rate limits are enforced
    globally across all API replicas. No in-memory state — no memory leak.
    """

    def __init__(self, app, calls_per_minute: int = 60):
        super().__init__(app)
        self.calls_per_minute = calls_per_minute

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health check and metrics endpoints
        if request.url.path in ("/health", "/metrics"):
            return await call_next(request)

        # Use X-Real-IP header if behind Nginx, fallback to client host
        client_ip = (
            request.headers.get("X-Real-IP")
            or (request.client.host if request.client else "unknown")
        )

        # Redis-backed sliding window (defensive: don't crash if redis not on state)
        redis = getattr(request.app.state, 'redis_client', None)
        if redis:
            allowed = await self._check_redis_rate_limit(redis, client_ip, request)
        else:
            # Fallback: in-memory (single-instance only, no leak)
            allowed = self._check_memory_rate_limit(request, client_ip)

        if not allowed:
            logger.warning(f"Rate limit exceeded for {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
                headers={"Retry-After": "60"},
            )

        response = await call_next(request)
        return response

    async def _check_redis_rate_limit(self, redis, client_ip: str, request: Request) -> bool:
        """Redis sliding window rate limit. No memory leak."""
        now_ms = int(time.time() * 1000)
        window_ms = 60_000  # 1 minute
        key = f"rate_limit:{client_ip}"

        try:
            # Remove entries outside the window
            await redis.zremrangebyscore(key, 0, now_ms - window_ms)
            # Count requests in current window
            count = await redis.zcard(key)
            if count is None:
                count = 0

            if count >= self.calls_per_minute:
                return False

            # Add current request timestamp
            await redis.zadd(key, {str(now_ms): now_ms})
            # Set expiry on the key (slightly longer than the window)
            await redis.expire(key, 120)
            return True
        except Exception as e:
            logger.error(f"Redis rate limit error: {e}")
            # Fail closed with a per-instance fallback budget (20 req/min)
            # Prevents DoS attackers from disabling Redis to bypass all limits
            return self._check_memory_rate_limit(request, client_ip, max_rpm=20)

    def _check_memory_rate_limit(self, request: Request, client_ip: str, max_rpm: int | None = None) -> bool:
        """Fallback in-memory rate limit. Single-instance only.
        When Redis is down, uses a conservative budget (max_rpm) to prevent
        complete bypass while avoiding blocking legitimate traffic."""
        threshold = max_rpm if max_rpm is not None else self.calls_per_minute
        if not hasattr(request.app.state, "_rate_limits"):
            request.app.state._rate_limits = {}

        now = time.time()
        limits = request.app.state._rate_limits

        # Cleanup: remove entries older than 2 minutes
        if not hasattr(request.app.state, "_last_cleanup"):
            request.app.state._last_cleanup = now

        if now - request.app.state._last_cleanup > 120:
            request.app.state._rate_limits = {
                k: v for k, v in limits.items()
                if now - v["window_start"] < 120
            }
            request.app.state._last_cleanup = now

        entry = limits.get(client_ip, {"window_start": now, "count": 0})
        if now - entry["window_start"] > 60:
            entry = {"window_start": now, "count": 0}

        entry["count"] += 1
        limits[client_ip] = entry

        return entry["count"] <= threshold