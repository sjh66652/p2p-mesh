"""
Auth-service-specific configuration.
Extends the shared BaseConfig with auth-related settings.
"""

import os
from dataclasses import dataclass, field

from shared.app.config import BaseConfig


@dataclass
class AuthConfig(BaseConfig):
    # ---- Auth-specific ----
    LOGIN_MAX_ATTEMPTS: int = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
    LOGIN_LOCKOUT_MINUTES: int = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "15"))
    BCRYPT_ROUNDS: int = int(os.getenv("BCRYPT_ROUNDS", "12"))
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))


settings = AuthConfig()
