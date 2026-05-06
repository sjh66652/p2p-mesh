"""
Configuration management for P2P Mesh Usage Service.
Reads from environment variables. NO hardcoded defaults for secrets.
"""

import os
import secrets
from dataclasses import dataclass, field


def _require_env(key: str) -> str:
    """Require an environment variable — crash early if missing."""
    value = os.getenv(key, "")
    if not value:
        raise RuntimeError(
            f"CRITICAL: Environment variable {key} is not set. "
            f"In production, all secrets MUST be provided via environment."
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

    # ---- Internal Service Auth ----
    INTERNAL_API_KEY: str = field(default_factory=lambda: _require_env("INTERNAL_API_KEY"))

    # ---- Server ----
    HOST: str = "0.0.0.0"
    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    # ---- Free Plan Limits ----
    FREE_MAX_REQUESTS_PER_MIN: int = int(os.getenv("FREE_MAX_REQUESTS_PER_MIN", "100"))
    FREE_MAX_CONNECTIONS: int = int(os.getenv("FREE_MAX_CONNECTIONS", "3"))
    FREE_MAX_BANDWIDTH_PER_DAY_GB: int = int(os.getenv("FREE_MAX_BANDWIDTH_PER_DAY_GB", "1"))

    # ---- Pro Plan Limits ----
    PRO_MAX_REQUESTS_PER_MIN: int = int(os.getenv("PRO_MAX_REQUESTS_PER_MIN", "1000"))
    PRO_MAX_CONNECTIONS: int = int(os.getenv("PRO_MAX_CONNECTIONS", "10"))
    PRO_MAX_BANDWIDTH_PER_DAY_GB: int = int(os.getenv("PRO_MAX_BANDWIDTH_PER_DAY_GB", "50"))

    # ---- Enterprise Plan Limits ----
    ENTERPRISE_MAX_REQUESTS_PER_MIN: int = int(os.getenv("ENTERPRISE_MAX_REQUESTS_PER_MIN", "10000"))
    ENTERPRISE_MAX_CONNECTIONS: int = int(os.getenv("ENTERPRISE_MAX_CONNECTIONS", "50"))
    ENTERPRISE_MAX_BANDWIDTH_PER_DAY_GB: int = int(os.getenv("ENTERPRISE_MAX_BANDWIDTH_PER_DAY_GB", "500"))

    # ---- Abuse Prevention ----
    ABUSE_BAN_DURATION_HOURS: int = int(os.getenv("ABUSE_BAN_DURATION_HOURS", "24"))

    # ---- Monitoring ----
    PROMETHEUS_ENABLED: bool = os.getenv("PROMETHEUS_ENABLED", "true").lower() == "true"

    # ---- Logging ----
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "WARNING")


settings = Settings()
