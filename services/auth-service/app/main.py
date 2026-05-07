"""
P2P Mesh - Auth Service
FastAPI Application Entry Point
Runs independently, binds to 0.0.0.0:8000.
"""

import asyncio
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.config import settings
from app.database import engine, Base, close_redis
from app.api import router
from shared.app.middleware import RateLimitMiddleware, LoggingMiddleware
from shared.app.metrics import (
    http_requests_total, http_request_duration_seconds,
    init_metrics,
)

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("auth-service.startup")


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


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests larger than 1MB."""
    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > 1 * 1024 * 1024:
            return Response(status_code=413, content="Request body too large")
        return await call_next(request)


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
            service="auth-service",
            status=str(response.status_code),
        ).inc()
        http_request_duration_seconds.labels(
            method=request.method,
            endpoint=endpoint,
            service="auth-service",
        ).observe(duration)
        return response


async def _connect_database_with_retry(app, max_retries=10, base_delay=2):
    """Connect to PostgreSQL with exponential backoff retry."""
    for attempt in range(1, max_retries + 1):
        try:
            log.info("Connecting to database (attempt %d/%d)...", attempt, max_retries)
            async with engine.begin() as conn:
                await conn.run_sync(_ensure_enum_types)
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


def _ensure_enum_types(connection):
    """Pre-create PostgreSQL ENUM types if they don't already exist."""
    from sqlalchemy import text
    result = connection.execute(text(
        "SELECT EXISTS(SELECT 1 FROM pg_type WHERE typname='userplan')"
    ))
    if not result.scalar():
        connection.execute(text("CREATE TYPE userplan AS ENUM ('FREE', 'PRO', 'ENTERPRISE')"))
        log.info("Created ENUM type: userplan")

    result = connection.execute(text(
        "SELECT EXISTS(SELECT 1 FROM pg_type WHERE typname='userrole')"
    ))
    if not result.scalar():
        connection.execute(text("CREATE TYPE userrole AS ENUM ('USER', 'ADMIN')"))
        log.info("Created ENUM type: userrole")


async def _connect_redis_with_retry(app, max_retries=10, base_delay=1):
    """Connect to Redis with exponential backoff retry."""
    for attempt in range(1, max_retries + 1):
        try:
            log.info("Connecting to Redis (attempt %d/%d)...", attempt, max_retries)
            from app.database import init_redis, redis_client
            await init_redis()
            app.state.redis_client = redis_client
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
    import os

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
    # Track which subsystems are healthy for the /health endpoint
    app.state.startup_complete = False
    app.state.db_ok = False
    app.state.redis_ok = False

    # ---- Database (with retry) ----
    await _connect_database_with_retry(app)

    # ---- Redis (with retry) ----
    await _connect_redis_with_retry(app)

    # ---- Security warnings ----
    _emit_security_warnings()

    app.state.startup_complete = True
    log.info("Startup complete -- API ready (db=%s redis=%s)", app.state.db_ok, app.state.redis_ok)

    init_metrics("auth-service")
    yield
    await close_redis()


app = FastAPI(
    title="P2P Mesh - Auth Service",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url=None,
)

# ---- Security Middleware (order matters) ----
app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(LoggingMiddleware)

# ---- Metrics Middleware (before rate limit so rate-limited requests are counted) ----
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

app.add_middleware(RateLimitMiddleware, calls_per_minute=settings.RATE_LIMIT_PER_MINUTE)

# ---- API Router ----
app.include_router(router, prefix="/api/auth", tags=["Authentication"])


@app.get("/health", tags=["System"])
async def health_check():
    if not getattr(app.state, 'startup_complete', False):
        return Response(status_code=503, content='{"status":"starting"}')
    return {"status": "healthy", "db": app.state.db_ok, "redis": app.state.redis_ok}


@app.get("/metrics", include_in_schema=False)
async def metrics(request: Request):
    """Prometheus metrics endpoint -- restricted to internal network."""
    if not getattr(settings, 'PROMETHEUS_ENABLED', True):
        return Response(status_code=404)
    client_ip = request.client.host if request.client else ""
    if not (client_ip.startswith("172.") or client_ip.startswith("10.") or client_ip == "127.0.0.1"):
        return Response(status_code=403, content="Forbidden")
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
