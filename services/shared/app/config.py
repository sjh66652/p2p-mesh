"""
Base configuration for P2P Mesh microservices.
Each service subclasses BaseConfig and adds its own settings.
Reads from environment variables. NO hardcoded defaults for secrets.
"""

import os
import secrets
from dataclasses import dataclass, field


def _require_env(key: str) -> str:
    """Require an environment variable -- crash early if missing."""
    value = os.getenv(key, "")
    if not value:
        raise RuntimeError(
            f"CRITICAL: Environment variable {key} is not set. "
            f"In production, all secrets MUST be provided via environment."
        )
    return value


@dataclass
class BaseConfig:
    # ---- Database ----
    DATABASE_URL: str = field(default_factory=lambda: _require_env("DATABASE_URL"))

    # ---- Redis ----
    REDIS_URL: str = field(default_factory=lambda: os.getenv(
        "REDIS_URL", "redis://localhost:6379/0"
    ))

    # ---- JWT ----
    # Falls back to a random key ONLY for dev/CI. Restart invalidates all tokens.
    JWT_SECRET: str = field(default_factory=lambda: os.getenv(
        "JWT_SECRET", ""
    ) or secrets.token_hex(64))
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_EXPIRE_DAYS: int = 7

    # ---- Service-to-service auth ----
    INTERNAL_API_KEY: str = field(default_factory=lambda: os.getenv(
        "INTERNAL_API_KEY", ""
    ) or secrets.token_hex(32))

    # ---- Server ----
    HOST: str = "0.0.0.0"
    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "WARNING")

    # ---- Service URLs (for inter-service communication) ----
    AUTH_SERVICE_URL: str = field(default_factory=lambda: os.getenv(
        "AUTH_SERVICE_URL", "http://auth-service:8000"
    ))
    USER_SERVICE_URL: str = field(default_factory=lambda: os.getenv(
        "USER_SERVICE_URL", "http://user-service:8000"
    ))
    SIGNALING_SERVICE_URL: str = field(default_factory=lambda: os.getenv(
        "SIGNALING_SERVICE_URL", "http://signaling-service:8000"
    ))
    RELAY_SERVICE_URL: str = field(default_factory=lambda: os.getenv(
        "RELAY_SERVICE_URL", "http://relay-service:8000"
    ))
    USAGE_SERVICE_URL: str = field(default_factory=lambda: os.getenv(
        "USAGE_SERVICE_URL", "http://usage-service:8000"
    ))
