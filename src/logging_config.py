from __future__ import annotations

import json
import logging
import sys

from pythonjsonlogger import jsonlogger

# Standard LogRecord attributes that are NOT extra fields.
_RESERVED_ATTRS = frozenset({
    "args", "created", "exc_info", "exc_text", "filename",
    "funcName", "levelname", "levelno", "lineno", "message",
    "module", "msecs", "msg", "name", "pathname", "process",
    "processName", "relativeCreated", "stack_info", "taskName",
    "thread", "threadName",
    # Added by uvicorn / third-party libraries:
    "color_message",
})

_LEVEL_SHORT = {"WARNING": "WARN", "CRITICAL": "CRIT"}


def _format_value(v: object) -> str:
    """Format a value for logfmt-style output."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (list, tuple, dict)):
        return json.dumps(v, separators=(",", ":"), default=str)
    s = str(v)
    if not s or " " in s or "|" in s or "=" in s or '"' in s:
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


class _StructuredTextFormatter(logging.Formatter):
    """Human-readable structured log format for Docker / terminal output.

    Format: ``TIMESTAMP LEVEL logger | message | key=val key=val``

    Designed for easy scanning by operators running ``docker logs`` *and*
    straightforward parsing by AI agents or log aggregation tools.
    """

    def format(self, record: logging.LogRecord) -> str:
        timestamp = self.formatTime(record, "%Y-%m-%dT%H:%M:%S")

        level = _LEVEL_SHORT.get(record.levelname, record.levelname)
        level = level.ljust(5)

        # Strip common "scanner." prefix for brevity.
        name = record.name
        if name.startswith("scanner."):
            name = name[8:]

        message = record.getMessage()

        line = f"{timestamp} {level} {name} | {message}"

        # Append extra fields as key=value pairs.
        extras = {
            k: v
            for k, v in record.__dict__.items()
            if k not in _RESERVED_ATTRS and not k.startswith("_")
        }
        if extras:
            pairs = " ".join(
                f"{k}={_format_value(v)}" for k, v in extras.items()
            )
            line += " | " + pairs

        # Exception / stack info on subsequent lines.
        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            line += "\n" + record.exc_text
        if record.stack_info:
            line += "\n" + self.formatStack(record.stack_info)

        return line


class _HealthFilter(logging.Filter):
    """Suppress noisy /health access logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        return '"GET /health' not in msg


def configure_logging(level: str, fmt: str = "text") -> None:
    handler = logging.StreamHandler(sys.stdout)

    if fmt == "json":
        formatter: logging.Formatter = jsonlogger.JsonFormatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
            rename_fields={
                "asctime": "timestamp",
                "levelname": "level",
                "name": "logger",
            },
        )
    else:
        formatter = _StructuredTextFormatter()

    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())

    # Quiet noisy libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)

    # Filter out /health spam from uvicorn access logs
    logging.getLogger("uvicorn.access").addFilter(_HealthFilter())
