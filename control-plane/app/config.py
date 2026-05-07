"""
Configuration management for P2P Mesh Network.
Reads from environment variables. NO hardcoded defaults for secrets.
"""

import os
import secrets
from dataclasses import dataclass, field
from typing import List


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
    # Postgres credentials MUST come from environment (never hardcoded).
    # Dev/CI only: no default — the docker-compose injects DATABASE_URL.
    DATABASE_URL: str = field(default_factory=lambda: _require_env("DATABASE_URL"))
    DATABASE_URL_SYNC: str = field(default_factory=lambda: os.getenv(
        "DATABASE_URL_SYNC", ""
    ) or _require_env("DATABASE_URL").replace("+asyncpg", ""))

    # ---- Redis ----
    REDIS_URL: str = field(default_factory=lambda: os.getenv(
        "REDIS_URL", "redis://localhost:6379/0"
    ))

    # ---- JWT ----
    # CRITICAL: Production MUST set JWT_SECRET via environment.
    # Falls back to a random key ONLY for dev/CI. Restart invalidates all tokens.
    JWT_SECRET: str = field(default_factory=lambda: os.getenv(
        "JWT_SECRET", ""
    ) or secrets.token_hex(64))
    JWT_ALGORITHM: str = "HS256"  # Fixed: only allow HS256 (prevents alg:none downgrade)
    JWT_RS256_PUBLIC_KEY: str = field(default_factory=lambda: os.getenv(
        "JWT_RS256_PUBLIC_KEY", ""
    ))
    JWT_ACCESS_EXPIRE_MINUTES: int = int(os.getenv("JWT_ACCESS_EXPIRE_MINUTES", "30"))
    JWT_REFRESH_EXPIRE_DAYS: int = int(os.getenv("JWT_REFRESH_EXPIRE_DAYS", "7"))

    # ---- Server ----
    HOST: str = "0.0.0.0"  # nosec B104  # standard Docker/server bind address
    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    MAX_REQUEST_BODY_BYTES: int = int(os.getenv("MAX_REQUEST_BODY_BYTES", str(1 * 1024 * 1024)))  # 1MB default

    # ---- CORS ----
    CORS_ORIGINS: List[str] = field(default_factory=lambda: os.getenv(
        "CORS_ORIGINS", "http://localhost:3000,http://localhost:8000"
    ).split(","))

    # ---- STUN Servers ----
    STUN_SERVERS: List[str] = field(default_factory=lambda: os.getenv(
        "STUN_SERVERS", "stun.l.google.com:19302"
    ).split(","))

    # ---- Relay ----
    # Relay nodes authenticate with this shared token (not JWT-based user auth).
    RELAY_AUTH_TOKEN: str = field(default_factory=lambda: os.getenv(
        "RELAY_AUTH_TOKEN",
        "relay-" + secrets.token_hex(32),  # dev-only fallback
    ))
    RELAY_CLEANUP_INTERVAL: int = int(os.getenv("RELAY_CLEANUP_INTERVAL", "300"))
    RELAY_MAX_LOAD: float = float(os.getenv("RELAY_MAX_LOAD", "0.8"))
    RELAY_MAX_CONNECTIONS_PER_DEVICE: int = int(os.getenv("RELAY_MAX_CONNECTIONS_PER_DEVICE", "50"))
    RELAY_MAX_REGISTRATION_RATE: int = int(os.getenv("RELAY_MAX_REGISTRATION_RATE", "5"))  # per IP per minute

    # ---- Billing ----
    FREE_PLAN_BANDWIDTH_MBPS: float = float(os.getenv("FREE_PLAN_BANDWIDTH_MBPS", "1"))
    PRO_PLAN_BANDWIDTH_MBPS: float = float(os.getenv("PRO_PLAN_BANDWIDTH_MBPS", "0"))
    ENTERPRISE_PLAN_BANDWIDTH_MBPS: float = float(os.getenv("ENTERPRISE_PLAN_BANDWIDTH_MBPS", "0"))
    MAX_TRAFFIC_REPORT_BYTES: int = int(os.getenv("MAX_TRAFFIC_REPORT_BYTES", str(10 * 1024 * 1024 * 1024)))  # 10GB per report cap

    # ---- Rate Limiting / Brute Force ----
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))
    LOGIN_MAX_ATTEMPTS: int = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
    LOGIN_LOCKOUT_MINUTES: int = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "15"))
    WS_MAX_MESSAGES_PER_SECOND: int = int(os.getenv("WS_MAX_MESSAGES_PER_SECOND", "20"))
    WS_MAX_MESSAGE_BYTES: int = int(os.getenv("WS_MAX_MESSAGE_BYTES", str(64 * 1024)))  # 64KB

    # ---- TLS ----
    TLS_ENABLED: bool = os.getenv("TLS_ENABLED", "false").lower() == "true"

    # ---- Monitoring ----
    PROMETHEUS_ENABLED: bool = os.getenv("PROMETHEUS_ENABLED", "true").lower() == "true"

    # ---- Logging ----
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "WARNING")
    LOG_FORMAT: str = os.getenv("LOG_FORMAT", "json")


settings = Settings()
