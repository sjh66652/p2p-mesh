"""
Signaling Service - P2P Mesh Network
FastAPI Application Entry Point
"""

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.config import settings
from app.api import router
from app.pubsub import init_pubsub, close_pubsub, pubsub_hub
from shared.app.metrics import (
    http_requests_total, http_request_duration_seconds,
    init_metrics,
)

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("signaling-service.startup")

# Redis client global
_redis_client: aioredis.Redis | None = None


def get_redis_client() -> aioredis.Redis | None:
    """Get the global Redis client instance."""
    return _redis_client


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to every response."""
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store, max-age=0"
        return response


class MetricsMiddleware(BaseHTTPMiddleware):
    """Record Prometheus metrics for every HTTP request."""
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        duration = time.time() - start
        endpoint = request.url.path
        # Normalize dynamic path parameters (UUIDs)
        for part in endpoint.split("/"):
            if part and all(c in "0123456789abcdef-" for c in part) and len(part) > 20:
                endpoint = endpoint.replace(part, "{id}")
        http_requests_total.labels(
            method=request.method,
            endpoint=endpoint,
            service="signaling-service",
            status=str(response.status_code),
        ).inc()
        http_request_duration_seconds.labels(
            method=request.method,
            endpoint=endpoint,
            service="signaling-service",
        ).observe(duration)
        return response


class LoggingMiddleware(BaseHTTPMiddleware):
    """Logs every HTTP request with timing and status."""
    async def dispatch(self, request: Request, call_next):
        start_time = asyncio.get_event_loop().time()
        log.info(
            '{"event":"request","method":"%s","path":"%s","client":"%s"}',
            request.method, request.url.path,
            request.client.host if request.client else "unknown",
        )
        response = await call_next(request)
        duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        log.info(
            '{"event":"response","method":"%s","path":"%s","status":%d,"duration_ms":%.2f}',
            request.method, request.url.path, response.status_code, duration_ms,
        )
        return response


async def _handle_remote_message(data: dict):
    """Deliver a message received from another node via PubSub to a local WebSocket."""
    from app.service import distributed_hub
    from app.service import signaling_hub

    msg_type = data.get("type")
    from_id_str = data.get("from")
    to_id_str = data.get("to")
    payload = data.get("payload", {})

    if not msg_type or not from_id_str or not to_id_str:
        logger.warning("Invalid remote message: missing fields")
        return

    try:
        from_id = uuid.UUID(from_id_str)
        to_id = uuid.UUID(to_id_str)
    except ValueError:
        logger.warning("Invalid UUID in remote message: from=%s to=%s", from_id_str, to_id_str)
        return

    # Reconstruct the message in the format expected by local WebSocket connections
    # Use the existing relay_signal logic which handles sender verification
    if msg_type in ("offer", "answer", "ice_candidate"):
        # Only deliver to the target local device
        conn = signaling_hub._connections.get(to_id)
        if conn:
            message = {
                "type": msg_type,
                "from": from_id_str,
                "to": to_id_str,
                "payload": payload,
            }
            try:
                await conn.ws.send_json(message)
                logger.debug("Remote message delivered: type=%s to=%s", msg_type, to_id_str)
            except Exception as e:
                logger.error("Failed to deliver remote message to %s: %s", to_id_str, e)
                await signaling_hub.disconnect(to_id)


async def _connect_redis_with_retry(app, max_retries=10, base_delay=1):
    """Connect to Redis with exponential backoff retry."""
    global _redis_client
    for attempt in range(1, max_retries + 1):
        try:
            log.info("Connecting to Redis (attempt %d/%d)...", attempt, max_retries)
            _redis_client = aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
            )
            await _redis_client.ping()
            app.state.redis_ok = True
            log.info("Redis connected on attempt %d", attempt)
            return
        except Exception as e:
            log.warning("Redis connection attempt %d failed: %s", attempt, e)
            if attempt == max_retries:
                log.critical("REDIS CONNECTION FAILED after %d attempts", max_retries, exc_info=True)
                raise
            delay = base_delay * (2 ** (attempt - 1))
            log.info("Retrying in %d seconds...", delay)
            await asyncio.sleep(delay)


def _emit_security_warnings():
    """Emit WARNING-level logs for security misconfigurations at startup."""
    if not os.getenv("JWT_SECRET"):
        log.warning(
            "SECURITY: JWT_SECRET not set -- using a random key that will invalidate "
            "all tokens on restart. Set JWT_SECRET in your environment for production."
        )
    if settings.DEBUG:
        log.warning(
            "SECURITY: DEBUG mode is ON -- exposes /docs, verbose errors, and "
            "potentially leaks stack traces to clients. Set DEBUG=false for production."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Track subsystem health
    app.state.startup_complete = False
    app.state.redis_ok = False

    # ---- Redis (with retry) ----
    try:
        await _connect_redis_with_retry(app)
    except Exception as e:
        log.critical("Redis connection failed, signaling service cannot function: %s", e)
        raise

    # ---- Redis PubSub for distributed signaling ----
    try:
        await init_pubsub(settings.NODE_ID, settings.REDIS_URL)
        pubsub_hub.set_message_handler(_handle_remote_message)
        app.state.pubsub_hub = pubsub_hub
        log.info("PubSub initialized on node=%s", settings.NODE_ID)
    except Exception as e:
        log.warning("PubSub initialization failed, running in local-only mode: %s", e)
        app.state.pubsub_hub = None

    # ---- Security warnings (non-fatal, informational) ----
    _emit_security_warnings()

    app.state.startup_complete = True
    log.info("Startup complete -- Signaling service ready (redis=%s)", app.state.redis_ok)

    init_metrics("signaling-service")

    yield

    # ---- Shutdown ----
    await close_pubsub()
    global _redis_client
    if _redis_client:
        await _redis_client.close()
        _redis_client = None
    log.info("Signaling service shut down")


app = FastAPI(
    title="P2P Mesh Signaling Service",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url=None,
)

# ---- Security Middleware ----
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(LoggingMiddleware)

# ---- Metrics Middleware ----
app.add_middleware(MetricsMiddleware)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS if hasattr(settings, 'CORS_ORIGINS') else ["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS if hasattr(settings, 'ALLOWED_HOSTS') else ["localhost", "127.0.0.1"],
)

# ---- API Router ----
app.include_router(router, prefix="")


@app.get("/")
async def root():
    return {"service": "signaling-service", "status": "running"}


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    redis_ok = get_redis_client() is not None
    return {
        "status": "healthy",
        "redis": redis_ok,
    }


@app.get("/metrics", include_in_schema=False)
async def metrics(request: Request):
    """Prometheus metrics endpoint -- restricted to internal networks."""
    if not settings.PROMETHEUS_ENABLED:
        return Response(status_code=404)

    client_ip = request.client.host if request.client else ""
    if not (client_ip.startswith("172.") or client_ip.startswith("10.") or client_ip == "127.0.0.1"):
        return Response(status_code=403, content="Forbidden")

    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)