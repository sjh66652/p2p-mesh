"""
Configuration management for P2P Mesh Network.
Reads from environment variables with sensible defaults.
"""

import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class Settings:
    # ---- Database ----
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://mesh:mesh_pass@localhost:5432/p2p_mesh",
    )
    DATABASE_URL_SYNC: str = os.getenv(
        "DATABASE_URL_SYNC",
        "postgresql://mesh:mesh_pass@localhost:5432/p2p_mesh",
    )

    # ---- Redis ----
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # ---- JWT ----
    JWT_SECRET: str = os.getenv("JWT_SECRET", "dev-secret-change-me")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "1440"))

    # ---- Server ----
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = os.getenv("DEBUG", "true").lower() == "true"

    # ---- STUN Servers ----
    STUN_SERVERS: List[str] = field(default_factory=lambda: os.getenv(
        "STUN_SERVERS",
        "stun.l.google.com:19302,stun1.l.google.com:19302",
    ).split(","))

    # ---- Relay ----
    RELAY_CLEANUP_INTERVAL: int = int(os.getenv("RELAY_CLEANUP_INTERVAL", "300"))
    RELAY_MAX_LOAD: float = float(os.getenv("RELAY_MAX_LOAD", "0.8"))

    # ---- Billing ----
    FREE_PLAN_BANDWIDTH_MBPS: float = float(os.getenv("FREE_PLAN_BANDWIDTH_MBPS", "1"))
    PRO_PLAN_BANDWIDTH_MBPS: float = float(os.getenv("PRO_PLAN_BANDWIDTH_MBPS", "0"))
    ENTERPRISE_PLAN_BANDWIDTH_MBPS: float = float(os.getenv("ENTERPRISE_PLAN_BANDWIDTH_MBPS", "0"))

    # ---- Rate Limiting ----
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))

    # ---- TLS ----
    TLS_ENABLED: bool = os.getenv("TLS_ENABLED", "false").lower() == "true"
    TLS_CERT_PATH: str = os.getenv("TLS_CERT_PATH", "")
    TLS_KEY_PATH: str = os.getenv("TLS_KEY_PATH", "")

    # ---- Monitoring ----
    PROMETHEUS_ENABLED: bool = os.getenv("PROMETHEUS_ENABLED", "true").lower() == "true"
    PROMETHEUS_PORT: int = int(os.getenv("PROMETHEUS_PORT", "9090"))

    # ---- Logging ----
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT: str = os.getenv("LOG_FORMAT", "json")


settings = Settings()
