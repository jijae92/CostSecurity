"""Logging helpers with basic masking."""

from __future__ import annotations

import logging
import os
from typing import Any, Mapping

_LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()


class MaskingFilter(logging.Filter):
    """Mask sensitive keys in log records."""

    SENSITIVE_KEYS = {"token", "secret", "password", "key"}

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: D401
        if hasattr(record, "extra") and isinstance(record.extra, Mapping):  # type: ignore[attr-defined]
            for key in list(record.extra.keys()):
                if key.lower() in self.SENSITIVE_KEYS and record.extra[key]:
                    record.extra[key] = self._mask(str(record.extra[key]))
        return True

    @staticmethod
    def _mask(value: str) -> str:
        return "***" if len(value) < 6 else f"{value[:3]}***{value[-3:]}"


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    handler.setFormatter(formatter)
    handler.addFilter(MaskingFilter())
    logger.addHandler(handler)
    logger.setLevel(_LOG_LEVEL)
    logger.propagate = False
    return logger


__all__ = ["get_logger"]
