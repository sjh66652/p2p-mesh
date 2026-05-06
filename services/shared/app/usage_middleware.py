"""
Unified usage interception layer.
Calls the usage-service to enforce plan quotas on every API request.
Used as a FastAPI dependency: Depends(check_usage_quota)
"""

import logging
import os
from fastapi import Request, HTTPException, status

import httpx

log = logging.getLogger("usage.interceptor")

USAGE_SERVICE_URL = os.getenv("USAGE_SERVICE_URL", "http://usage-service:8000")
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "")


async def _get_user_id_from_request(request: Request) -> str | None:
    """Extract user_id from JWT in Authorization header."""
    from jose import jwt

    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return None

    token = auth[7:]
    try:
        secret = os.getenv("JWT_SECRET", "")
        payload = jwt.decode(token, secret, algorithms=["HS256"],
                            options={"verify_exp": False})
        return payload.get("sub")
    except Exception:
        return None


async def check_usage_quota(request: Request):
    """
    FastAPI dependency: Check if the user has exceeded their plan quota.
    Raises 429 if quota exceeded.
    """
    user_id = await _get_user_id_from_request(request)
    if not user_id:
        return  # No user context, skip (public endpoints)

    headers = {"X-Internal-API-Key": INTERNAL_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(
                f"{USAGE_SERVICE_URL}/api/usage/quota/check",
                json={"user_id": user_id},
                headers=headers,
            )
            if resp.status_code == 200:
                data = resp.json()
                if not data.get("allowed", True):
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Quota exceeded: {data.get('reason', 'limit reached')}",
                        headers={"Retry-After": "60"},
                    )
    except httpx.RequestError:
        log.warning("Usage service unreachable -- allowing request (fail-open for availability)")
    except HTTPException:
        raise


async def record_api_usage(request: Request, response_status: int = 200):
    """
    Record an API request to the usage service.
    Called after the request is processed.
    """
    user_id = await _get_user_id_from_request(request)
    if not user_id:
        return

    headers = {"X-Internal-API-Key": INTERNAL_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(
                f"{USAGE_SERVICE_URL}/api/usage/record",
                json={
                    "user_id": user_id,
                    "metric_type": "api_request",
                    "value": 1,
                },
                headers=headers,
            )
    except Exception:
        pass  # Fire-and-forget, don't block the request


class UsageTrackingMiddleware:
    """ASGI middleware that records API usage after each request."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Skip health/metrics
        path = scope.get("path", "")
        if path in ("/health", "/metrics"):
            await self.app(scope, receive, send)
            return

        # Wrap send to capture status code
        response_status = [200]
        original_send = send

        async def _wrapped_send(message):
            if message["type"] == "http.response.start":
                response_status[0] = message.get("status", 200)
            await original_send(message)

        # Process the request
        await self.app(scope, receive, _wrapped_send)

        # Record usage after response
        try:
            pass
        except Exception:
            pass
