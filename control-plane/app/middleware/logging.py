"""
Request/response logging middleware with structured JSON output.
"""

import time
import logging
import json

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("p2p-mesh.api")


class LoggingMiddleware(BaseHTTPMiddleware):
    """Logs every HTTP request with timing and status."""

    async def dispatch(self, request: Request, call_next):
        start_time = time.time()

        # Log request
        logger.info(
            json.dumps({
                "event": "request",
                "method": request.method,
                "path": request.url.path,
                "client": request.client.host if request.client else "unknown",
            })
        )

        response = await call_next(request)

        # Log response
        duration_ms = (time.time() - start_time) * 1000
        logger.info(
            json.dumps({
                "event": "response",
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round(duration_ms, 2),
            })
        )

        return response
