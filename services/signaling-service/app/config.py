"""
Configuration for signaling-service.
Reads from environment variables with sensible defaults for development.
"""

import os
import platform
import secrets
from dataclasses import dataclass, field


@dataclass
class Settings:
    # ---- JWT ----
    # CRITICAL: Production MUST set JWT_SECRET via environment.
    # Falls back to a random key ONLY for dev/CI. Restart invalidates all tokens.
    JWT_SECRET: str = field(default_factory=lambda: os.getenv(
        "JWT_SECRET", ""
    ) or secrets.token_hex(64))
    JWT_ALGORITHM: str = "HS256"  # Fixed: only allow HS256 (prevents alg:none downgrade)

    # ---- Redis ----
    REDIS_URL: str = field(default_factory=lambda: os.getenv(
        "REDIS_URL", "redis://localhost:6379/0"
    ))

    # ---- Connection Limits ----
    MAX_CONNECTIONS: int = int(os.getenv("MAX_CONNECTIONS", "10000"))
    MAX_CONNECTIONS_PER_USER: int = int(os.getenv("MAX_CONNECTIONS_PER_USER", "5"))

    # ---- WebSocket ----
    WS_MAX_MESSAGES_PER_SECOND: int = int(os.getenv("WS_MAX_MESSAGES_PER_SECOND", "20"))
    WS_MAX_MESSAGE_BYTES: int = int(os.getenv("WS_MAX_MESSAGE_BYTES", str(64 * 1024)))  # 64KB

    # ---- Server ----
    HOST: str = "0.0.0.0"
    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "WARNING")

    # ---- Auth Service ----
    AUTH_SERVICE_URL: str = field(default_factory=lambda: os.getenv(
        "AUTH_SERVICE_URL", "http://auth-service:8000"
    ))

    # ---- Distributed Pub/Sub ----
    NODE_ID: str = field(default_factory=lambda: os.getenv(
        "NODE_ID", ""
    ) or platform.node())

    # ---- Internal API Key ----
    INTERNAL_API_KEY: str = field(default_factory=lambda: os.getenv(
        "INTERNAL_API_KEY", ""
    ) or secrets.token_hex(32))

    # ---- Prometheus ----
    PROMETHEUS_ENABLED: bool = os.getenv("PROMETHEUS_ENABLED", "true").lower() == "true"


settings = Settings()
