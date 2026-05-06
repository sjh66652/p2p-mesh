import os
from dataclasses import dataclass, field

@dataclass
class WorkerConfig:
    DATABASE_URL: str = field(default_factory=lambda: os.getenv("DATABASE_URL", ""))
    REDIS_URL: str = field(default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    # Queue names
    USAGE_QUEUE: str = "queue:usage"
    LOG_QUEUE: str = "queue:logs"
    CLEANUP_QUEUE: str = "queue:cleanup"
    # Processing intervals
    USAGE_BATCH_INTERVAL: int = int(os.getenv("USAGE_BATCH_INTERVAL", "5"))
    CLEANUP_INTERVAL: int = int(os.getenv("CLEANUP_INTERVAL", "300"))  # 5 minutes

settings = WorkerConfig()
