"""
Rate limiting middleware using Redis-backed sliding window algorithm.
"""

import time
import logging
from collections import defaultdict

from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple in-memory rate limiting middleware.
    For production, replace with Redis-backed implementation.

    Limits requests per minute per client IP.
    """

    def __init__(self, app, calls_per_minute: int = 60):
        super().__init__(app)
        self.calls_per_minute = calls_per_minute
        self._window_starts: dict[str, float] = {}
        self._counts: dict[str, int] = defaultdict(int)

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health check and metrics endpoints
        if request.url.path in ("/health", "/metrics"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.time()

        # Reset counter each minute
        window_key = f"{client_ip}:{int(now // 60)}"
        if window_key not in self._window_starts:
            self._window_starts = {
                k: v for k, v in self._window_starts.items()
                if now - v < 120
            }
            self._window_starts[window_key] = now
            self._counts[window_key] = 0

        self._counts[window_key] += 1

        if self._counts[window_key] > self.calls_per_minute:
            logger.warning(f"Rate limit exceeded for {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
                headers={"Retry-After": "60"},
            )

        response = await call_next(request)
        return response
