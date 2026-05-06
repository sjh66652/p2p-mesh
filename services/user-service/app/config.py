"""
User-service-specific configuration.
Extends the shared BaseConfig with user/device related settings.
"""

import os
from dataclasses import dataclass

from shared.app.config import BaseConfig


@dataclass
class UserConfig(BaseConfig):
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))


settings = UserConfig()
