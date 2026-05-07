"""
Configuration for relay-service.
Reads from environment variables with sensible defaults for development.
"""

import os
import secrets
from dataclasses import dataclass, field


def _require_env(key: str) -> str:
    """Require an environment variable -- crash early if missing."""
    value = os.getenv(key, "")
    if not value:
        raise RuntimeError(
            "A required configuration value is missing. "
            "Please ensure all required environment variables are set."
        )
    return value


@dataclass
class Settings:
    # ---- Database ----
    DATABASE_URL: str = field(default_factory=lambda: _require_env("DATABASE_URL"))

    # ---- Redis ----
    REDIS_URL: str = field(default_factory=lambda: os.getenv(
        "REDIS_URL", "redis://localhost:6379/0"
    ))

    # ---- JWT ----
    JWT_SECRET: str = field(default_factory=lambda: os.getenv(
        "JWT_SECRET", ""
    ) or secrets.token_hex(64))
    JWT_ALGORITHM: str = "HS256"

    # ---- Relay ----
    RELAY_AUTH_TOKEN: str = field(default_factory=lambda: os.getenv(
        "RELAY_AUTH_TOKEN",
        "relay-" + secrets.token_hex(32),
    ))
    RELAY_CLEANUP_INTERVAL: int = int(os.getenv("RELAY_CLEANUP_INTERVAL", "300"))
    RELAY_MAX_LOAD: float = float(os.getenv("RELAY_MAX_LOAD", "0.8"))
    RELAY_MAX_CONNECTIONS_PER_DEVICE: int = int(os.getenv("RELAY_MAX_CONNECTIONS_PER_DEVICE", "50"))
    RELAY_MAX_REGISTRATION_RATE: int = int(os.getenv("RELAY_MAX_REGISTRATION_RATE", "5"))

    # ---- Server ----
    HOST: str = "0.0.0.0"
    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "WARNING")

    # ---- Prometheus ----
    PROMETHEUS_ENABLED: bool = os.getenv("PROMETHEUS_ENABLED", "true").lower() == "true"


settings = Settings()
