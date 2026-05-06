"""
P2P Mesh Network - Usage Service (Security-Hardened)
FastAPI Application Entry Point for resource quota management.
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
from app.database import engine, Base
from app.api import router
from shared.app.metrics import (
    http_requests_total, http_request_duration_seconds,
    init_metrics,
)

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("p2p-usage.startup")


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
            service="usage-service",
            status=str(response.status_code),
        ).inc()
        http_request_duration_seconds.labels(
            method=request.method,
            endpoint=endpoint,
            service="usage-service",
        ).observe(duration)
        return response


async def _connect_database_with_retry(app, max_retries=10, base_delay=2):
    """Connect to PostgreSQL with exponential backoff retry."""
    for attempt in range(1, max_retries + 1):
        try:
            log.info("Connecting to database (attempt %d/%d)...", attempt, max_retries)
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.startup_complete = False
    app.state.db_ok = False
    app.state.redis_ok = False

    await _connect_database_with_retry(app)
    await _connect_redis_with_retry(app)

    app.state.startup_complete = True
    log.info("Startup complete — Usage Service ready (db=%s redis=%s)", app.state.db_ok, app.state.redis_ok)

    init_metrics("usage-service")

    yield

    from app.database import close_redis
    await close_redis()


app = FastAPI(
    title="P2P Mesh Usage Service",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url=None,
)

# ---- Security Middleware ----
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(MetricsMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Internal-API-Key"],
    max_age=600,
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"],
)

# ---- API Router ----
app.include_router(router, prefix="/api/usage", tags=["Usage"])


@app.get("/health")
async def health_check():
    """Health check endpoint for container orchestration."""
    db_ok = getattr(app.state, "db_ok", False)
    redis_ok = getattr(app.state, "redis_ok", False)
    startup_complete = getattr(app.state, "startup_complete", False)

    if not startup_complete:
        return Response(status_code=503, content='{"status":"starting"}')

    if not db_ok or not redis_ok:
        return Response(
            status_code=503,
            content=f'{{"status":"degraded","db":{str(db_ok).lower()},"redis":{str(redis_ok).lower()}}}',
        )

    return {"status": "healthy", "db": db_ok, "redis": redis_ok}


@app.get("/metrics", include_in_schema=False)
async def metrics(request: Request):
    """Prometheus metrics endpoint -- restricted to internal Docker network."""
    if not settings.PROMETHEUS_ENABLED:
        return Response(status_code=404)

    client_ip = request.client.host if request.client else ""
    if not (client_ip.startswith("172.") or client_ip.startswith("10.") or client_ip == "127.0.0.1"):
        return Response(status_code=403, content="Forbidden")

    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
