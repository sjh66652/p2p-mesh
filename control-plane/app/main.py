"""
P2P Mesh Network - Control Plane (Security-Hardened)
FastAPI Application Entry Point
"""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.config import settings
from app.database import engine, Base
from app.api import auth, devices, network, relay, traffic, billing, ws, candidates
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.logging import LoggingMiddleware

import logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("p2p-mesh.startup")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to every response."""
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store, max-age=0"
        # Don't set HSTS here — Nginx handles it at the edge
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests larger than MAX_REQUEST_BODY_BYTES."""
    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > settings.MAX_REQUEST_BODY_BYTES:
            return Response(status_code=413, content="Request body too large")
        return await call_next(request)


async def _connect_database_with_retry(app, max_retries=10, base_delay=2):
    """Connect to PostgreSQL with exponential backoff retry.
    Handles ENUM type collision by checking for existing types before create_all."""
    for attempt in range(1, max_retries + 1):
        try:
            log.info("Connecting to database (attempt %d/%d)...", attempt, max_retries)
            async with engine.begin() as conn:
                # Ensure PostgreSQL ENUM types exist before create_all to avoid
                # "type already exists" errors on container restart.
                # SAEnum creates native PG ENUMs which lack IF NOT EXISTS support.
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
    """Pre-create PostgreSQL ENUM types if they don't already exist.
    SAEnum uses enum member NAMES (not values) as PG ENUM labels,
    so 'UserPlan.FREE' → 'FREE' in PostgreSQL, not 'free'.
    This is called before create_all to avoid type-already-exists errors."""
    from sqlalchemy import text
    # Check and create userplan ENUM using member NAMES (uppercase)
    result = connection.execute(text(
        "SELECT EXISTS(SELECT 1 FROM pg_type WHERE typname='userplan')"
    ))
    if not result.scalar():
        connection.execute(text("CREATE TYPE userplan AS ENUM ('FREE', 'PRO', 'ENTERPRISE')"))
        log.info("Created ENUM type: userplan")

    # Check and create userrole ENUM using member NAMES (uppercase)
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
    """Emit WARNING-level logs for security misconfigurations at startup.
    Non-fatal — the service still starts, but operators see these in logs."""
    import os

    if not os.getenv("JWT_SECRET"):
        log.warning(
            "SECURITY: JWT_SECRET not set — using a random key that will invalidate "
            "all tokens on restart. Set JWT_SECRET in your environment for production."
        )
    if not os.getenv("RELAY_AUTH_TOKEN"):
        log.warning(
            "SECURITY: RELAY_AUTH_TOKEN not set — using a random key. "
            "Relay nodes will fail to authenticate after restart."
        )
    if settings.DEBUG:
        log.warning(
            "SECURITY: DEBUG mode is ON — exposes /docs, verbose errors, and "
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

    # ---- Relay health check (non-critical) ----
    relay_task = None
    try:
        log.info("Starting relay health check...")
        from app.services.relay_service import start_relay_health_check
        relay_task = start_relay_health_check()
        log.info("Relay health check started")
    except Exception as e:
        log.warning("RELAY HEALTH CHECK START FAILED (non-fatal): %s", e, exc_info=True)

    # ---- Security warnings (non-fatal, informational) ----
    _emit_security_warnings()

    app.state.startup_complete = True
    log.info("Startup complete — API ready (db=%s redis=%s)", app.state.db_ok, app.state.redis_ok)
    yield
    from app.database import close_redis
    await close_redis()
    if relay_task:
        relay_task.cancel()


app = FastAPI(
    title="P2P Mesh Network API",
    version="1.0.0",
    lifespan=lifespan,
    # Disable OpenAPI docs in production (override with DOCS_ENABLED=true)
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url=None,
)

# ---- Security Middleware (order matters) ----
app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(LoggingMiddleware)

# CORS: restrict to configured origins in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS if not settings.DEBUG else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"],  # Nginx handles host validation at edge
)

app.add_middleware(RateLimitMiddleware, calls_per_minute=settings.RATE_LIMIT_PER_MINUTE)

# ---- API Routers ----
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(devices.router, prefix="/api/v1/devices", tags=["Devices"])
app.include_router(network.router, prefix="/api/v1/network", tags=["Network"])
app.include_router(relay.router, prefix="/api/v1/relay", tags=["Relay"])
app.include_router(traffic.router, prefix="/api/v1/traffic", tags=["Traffic"])
app.include_router(billing.router, prefix="/api/v1/billing", tags=["Billing"])
app.include_router(ws.router, prefix="/api/v1/ws", tags=["Signaling"])
app.include_router(candidates.router, prefix="/api/v1/candidates", tags=["NAT Traversal"])


@app.get("/health", tags=["System"])
async def health_check():
    if not getattr(app.state, 'startup_complete', False):
        return Response(status_code=503, content='{"status":"starting"}')
    return {"status": "healthy", "db": app.state.db_ok, "redis": app.state.redis_ok}


@app.get("/metrics", include_in_schema=False)
async def metrics(request: Request):
    """Prometheus metrics endpoint — restricted to internal Prometheus scraper.
    In production, Nginx should additionally restrict this to the Prometheus IP."""
    if not settings.PROMETHEUS_ENABLED:
        return Response(status_code=404)
    # Only allow internal Docker network or localhost
    client_ip = request.client.host if request.client else ""
    if not (client_ip.startswith("172.") or client_ip.startswith("10.") or client_ip == "127.0.0.1"):
        return Response(status_code=403, content="Forbidden")
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
