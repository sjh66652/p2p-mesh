"""
P2P Mesh Network - Control Plane
FastAPI Application Entry Point

A production-grade P2P mesh networking system with:
- JWT/OAuth2 authentication
- Device registration and management
- WebSocket real-time signaling
- NAT traversal path selection
- Relay node orchestration
- Billing and traffic management
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.config import settings
from app.database import engine, Base
from app.api import auth, devices, network, relay, traffic, billing, ws
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.logging import LoggingMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    from app.database import init_redis
    await init_redis()
    from app.services.relay_service import start_relay_health_check
    relay_task = start_relay_health_check()
    yield
    from app.database import close_redis
    await close_redis()
    relay_task.cancel()


app = FastAPI(
    title="P2P Mesh Network API",
    version="1.0.0",
    description="Production-grade P2P mesh networking control plane",
    lifespan=lifespan,
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])
app.add_middleware(LoggingMiddleware)
app.add_middleware(RateLimitMiddleware, calls_per_minute=settings.RATE_LIMIT_PER_MINUTE)

app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(devices.router, prefix="/api/v1/devices", tags=["Devices"])
app.include_router(network.router, prefix="/api/v1/network", tags=["Network"])
app.include_router(relay.router, prefix="/api/v1/relay", tags=["Relay"])
app.include_router(traffic.router, prefix="/api/v1/traffic", tags=["Traffic"])
app.include_router(billing.router, prefix="/api/v1/billing", tags=["Billing"])
app.include_router(ws.router, prefix="/api/v1/ws", tags=["Signaling"])


@app.get("/health", tags=["System"])
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}


@app.get("/metrics", tags=["System"])
async def metrics():
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    from fastapi.responses import Response
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
