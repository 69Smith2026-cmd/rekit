from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    log_level: str = "INFO"
    max_size: int = 50 * 1024 * 1024

    @classmethod
    def from_env(cls) -> "Settings":
        level = os.getenv("LOG_LEVEL", "INFO").upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            level = "INFO"
        try:
            max_size = int(os.getenv("MAX_SIZE", "52428800"))
        except ValueError:
            max_size = 50 * 1024 * 1024
        return cls(log_level=level, max_size=max_size)


settings = Settings.from_env()
