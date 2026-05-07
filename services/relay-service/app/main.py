"""
Relay Service - P2P Mesh Network
FastAPI Application Entry Point
"""

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.config import settings
from app.api import router
from shared.app.metrics import (
    http_requests_total, http_request_duration_seconds,
    init_metrics,
)

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("relay-service.startup")


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
            service="relay-service",
            status=str(response.status_code),
        ).inc()
        http_request_duration_seconds.labels(
            method=request.method,
            endpoint=endpoint,
            service="relay-service",
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


async def _connect_database_with_retry(app, max_retries=10, base_delay=2):
    """Connect to PostgreSQL with exponential backoff retry."""
    for attempt in range(1, max_retries + 1):
        try:
            log.info("Connecting to database (attempt %d/%d)...", attempt, max_retries)
            from app.database import engine, Base
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            app.state.db_ok = True
            log.info("Database tables ensured on attempt %d", attempt)
            return
        except Exception as e:
            log.warning("Database connection attempt %d failed: %s", attempt, e)
            if attempt == max_retries:
                log.critical("DATABASE CONNECTION FAILED after %d attempts", max_retries, exc_info=True)
                raise
            delay = base_delay * (2 ** (attempt - 1))
            log.info("Retrying in %d seconds...", delay)
            await asyncio.sleep(delay)


async def _connect_redis_with_retry(app, max_retries=10, base_delay=1):
    """Connect to Redis with exponential backoff retry."""
    for attempt in range(1, max_retries + 1):
        try:
            log.info("Connecting to Redis (attempt %d/%d)...", attempt, max_retries)
            from app.database import init_redis
            await init_redis()
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
    if not os.getenv("RELAY_AUTH_TOKEN"):
        log.warning(
            "SECURITY: RELAY_AUTH_TOKEN not set -- using a random key. "
            "Relay nodes will fail to authenticate after restart."
        )
    if settings.DEBUG:
        log.warning(
            "SECURITY: DEBUG mode is ON -- exposes /docs, verbose errors, and "
            "potentially leaks stack traces to clients. Set DEBUG=false for production."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Track which subsystems are healthy for the /health endpoint
    app.state.startup_complete = False
    app.state.db_ok = False
    app.state.redis_ok = False

    # ---- Database (with retry) ----
    try:
        await _connect_database_with_retry(app)
    except Exception as e:
        log.critical("Database connection failed, relay service cannot function: %s", e)
        raise

    # ---- Redis (with retry) ----
    try:
        await _connect_redis_with_retry(app)
    except Exception as e:
        log.warning("Redis connection failed (non-fatal): %s", e)
        # Redis is not critical for relay-service operations

    # ---- Relay health check (non-critical) ----
    relay_task = None
    try:
        log.info("Starting relay health check...")
        from app.service import start_relay_health_check
        relay_task = start_relay_health_check()
        log.info("Relay health check started")
    except Exception as e:
        log.warning("RELAY HEALTH CHECK START FAILED (non-fatal): %s", e, exc_info=True)

    # ---- Security warnings (non-fatal, informational) ----
    _emit_security_warnings()

    app.state.startup_complete = True
    log.info("Startup complete -- Relay service ready (db=%s redis=%s)", app.state.db_ok, app.state.redis_ok)

    init_metrics("relay-service")

    yield

    # ---- Shutdown ----
    from app.database import close_redis
    await close_redis()
    if relay_task:
        relay_task.cancel()
    log.info("Relay service shut down")


app = FastAPI(
    title="P2P Mesh Relay Service",
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

# ---- API Router ----
app.include_router(router, prefix="/api/relay")


@app.get("/")
async def root():
    return {"service": "relay-service", "status": "running"}


@app.get("/health")
async def health_check():
    if not getattr(app.state, 'startup_complete', False):
        return Response(status_code=503, content='{"status":"starting"}')
    return {
        "status": "healthy",
        "db": app.state.db_ok,
        "redis": app.state.redis_ok,
    }
