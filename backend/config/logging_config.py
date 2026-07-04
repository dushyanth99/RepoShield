"""
Structured JSON Logging — config/logging_config.py

Replaces the default unstructured Python logging output with a machine-readable
JSON stream that cloud aggregators (Datadog, Splunk, Cloud Logging) can parse
without field extraction rules.

Zero external dependencies — built exclusively on the stdlib logging module.

Usage
-----
Call setup_production_logging() once at the very top of main.py before any
other import triggers logging. All subsequent loggers inherit the JSON handler
from the root logger automatically.
"""

import json
import logging
import sys
import time
import traceback as tb
from datetime import datetime, timezone


class JSONLogFormatter(logging.Formatter):
    """
    Formats every LogRecord as a single-line JSON object.

    Standard fields emitted on every line
    --------------------------------------
    timestamp   : ISO-8601 UTC timestamp
    level       : DEBUG / INFO / WARNING / ERROR / CRITICAL
    logger      : dotted logger name (e.g. "reposhield.shield_agent")
    message     : formatted log message
    module      : source module filename (without .py)
    function    : function that called the logger
    line        : source line number
    process     : PID
    thread      : thread ID

    Optional fields appended when present
    --------------------------------------
    exception   : formatted exception + traceback (only when exc_info is set)
    <any key>   : extra dict fields passed via logger.info("msg", extra={...})
    """

    # Fields in LogRecord that we do NOT want to bubble up into the JSON body
    # (they are already mapped to named keys, or are internal bookkeeping)
    _RESERVED: frozenset[str] = frozenset({
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "id", "levelname", "levelno", "lineno", "message",
        "module", "msecs", "msg", "name", "pathname", "process",
        "processName", "relativeCreated", "stack_info", "taskName",
        "thread", "threadName",
    })

    def format(self, record: logging.LogRecord) -> str:
        # Ensure record.message is populated before we inspect it
        record.message = record.getMessage()

        log_payload: dict = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc)
                                .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "level":    record.levelname,
            "logger":   record.name,
            "message":  record.message,
            "module":   record.module,
            "function": record.funcName,
            "line":     record.lineno,
            "process":  record.process,
            "thread":   record.thread,
        }

        # Merge any extra= fields the caller supplied, skipping reserved keys
        for key, value in record.__dict__.items():
            if key not in self._RESERVED and not key.startswith("_"):
                try:
                    json.dumps(value)          # only include JSON-serialisable values
                    log_payload[key] = value
                except (TypeError, ValueError):
                    log_payload[key] = str(value)

        # Append formatted exception + traceback when present
        if record.exc_info:
            log_payload["exception"] = self.formatException(record.exc_info)
        elif record.exc_text:
            log_payload["exception"] = record.exc_text

        # Append stack_info when present
        if record.stack_info:
            log_payload["stack_info"] = self.formatStack(record.stack_info)

        return json.dumps(log_payload, ensure_ascii=False, default=str)


def setup_production_logging(level: int = logging.INFO) -> None:
    """
    Configure the root logger with a single JSON StreamHandler writing to stdout.

    Rules
    -----
    - Called once at application startup, before any module-level loggers fire.
    - Removes all existing handlers to prevent duplicate / unformatted output.
    - Suppresses noisy third-party loggers that flood the stream at DEBUG level
      (SQLAlchemy engine, uvicorn access log, httpx).

    Args:
        level: Minimum log level for the root logger. Default: logging.INFO.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Purge any pre-existing handlers (e.g. basicConfig defaults)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        handler.close()

    # Single stdout handler with JSON formatter
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(JSONLogFormatter())
    stream_handler.setLevel(level)
    root_logger.addHandler(stream_handler)

    # -----------------------------------------------------------------------
    # Silence chatty third-party loggers — they emit at INFO/DEBUG by default
    # -----------------------------------------------------------------------
    _NOISY_LOGGERS: list[str] = [
        "sqlalchemy.engine",
        "sqlalchemy.pool",
        "uvicorn.access",
        "httpx",
        "httpcore",
    ]
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)

    logging.getLogger("reposhield").info(
        "JSON structured logging initialised",
        extra={"root_level": logging.getLevelName(level)},
    )
