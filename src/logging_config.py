from __future__ import annotations

import logging
import sys

from pythonjsonlogger import jsonlogger


class _HealthFilter(logging.Filter):
    """Suppress noisy /health access logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        return '"GET /health' not in msg


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    formatter = jsonlogger.JsonFormatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
        rename_fields={
            "asctime": "timestamp",
            "levelname": "level",
            "name": "logger",
        },
    )
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())

    # Quiet noisy libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)

    # Filter out /health spam from uvicorn access logs
    logging.getLogger("uvicorn.access").addFilter(_HealthFilter())
