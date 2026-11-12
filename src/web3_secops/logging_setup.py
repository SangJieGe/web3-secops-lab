"""Structured JSON Lines logging (stdlib only).

Every log line is a single JSON object on stdout, which is what a log shipper
(Filebeat → Wazuh, Loki, CloudWatch) wants. The logger intentionally has no
third-party dependency and never formats secrets: callers pass already-redacted
values.

Required keys on every record: ``timestamp``, ``level``, ``event``.
Optional when applicable: ``chain_id``, ``block_number``, ``duration_ms``.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from typing import Any

_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

# Attributes present on a stdlib LogRecord that are NOT part of our structured
# payload. Everything else was passed via `extra=` and belongs in the output.
_RESERVED = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "taskName",
        "message",
        "asctime",
    }
)


class JsonLineFormatter(logging.Formatter):
    """Render a :class:`logging.LogRecord` as one compact JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "event": record.getMessage(),
            "logger": record.name,
        }

        # Structured fields supplied by the caller.
        for key, value in record.__dict__.items():
            if key in _RESERVED or key.startswith("_"):
                continue
            payload[key] = value

        if record.exc_info:
            # Exception text is kept but never includes the RPC URL unless the
            # caller put it there; httpx messages contain only the host+path,
            # and we redact before logging in rpc_client.
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)


class StructuredLogger:
    """Thin wrapper so callers write ``log.info("event", key=value)``."""

    __slots__ = ("_logger",)

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def _log(self, level: int, event: str, **fields: Any) -> None:
        if not self._logger.isEnabledFor(level):
            return
        self._logger.log(level, event, extra=fields)

    def debug(self, event: str, **fields: Any) -> None:
        self._log(logging.DEBUG, event, **fields)

    def info(self, event: str, **fields: Any) -> None:
        self._log(logging.INFO, event, **fields)

    def warning(self, event: str, **fields: Any) -> None:
        self._log(logging.WARNING, event, **fields)

    def error(self, event: str, **fields: Any) -> None:
        self._log(logging.ERROR, event, **fields)

    def critical(self, event: str, **fields: Any) -> None:
        self._log(logging.CRITICAL, event, **fields)


class _StdoutHandler(logging.StreamHandler):
    """StreamHandler that always writes to the *current* ``sys.stdout``.

    A plain ``StreamHandler(stream=sys.stdout)`` captures whatever object
    ``sys.stdout`` pointed at when the handler was constructed. Under pytest's
    capture, or any tool that swaps ``sys.stdout`` after import, that stale
    reference means records vanish. Resolving the stream at emit time keeps the
    output where the operator (and the test harness) is actually looking.
    """

    def __init__(self) -> None:
        super().__init__(stream=sys.stdout)

    @property  # type: ignore[override]
    def stream(self):
        return sys.stdout

    @stream.setter
    def stream(self, value) -> None:
        # Ignore assignment: the stream is always resolved dynamically.
        pass


_handler: logging.Handler | None = None


def configure_logging(level: str = "INFO") -> None:
    """Install the JSON Lines handler on the ``web3_secops`` logger tree.

    Idempotent: calling it twice does not duplicate handlers, and it is safe to
    call after ``get_logger()`` — which happens on import, since every module
    binds a module-level ``log``. The handler is installed exactly once; later
    calls only adjust the level.
    """
    global _handler
    root = logging.getLogger("web3_secops")
    resolved = _LEVELS.get(level.upper(), logging.INFO)
    root.setLevel(resolved)

    if _handler is None:
        handler = _StdoutHandler()
        handler.setFormatter(JsonLineFormatter())
        root.addHandler(handler)
        root.propagate = False  # do not double-emit through the stdlib root
        _handler = handler

    _handler.setLevel(resolved)


def reset_logging() -> None:
    """Remove handlers. Used by tests, not by production code."""
    global _handler
    root = logging.getLogger("web3_secops")
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    _handler = None


def get_logger(name: str) -> StructuredLogger:
    """Return a structured logger inside the ``web3_secops`` tree.

    The handler is installed on the ``web3_secops`` logger with
    ``propagate=False``, so only loggers *under* that name reach it. Two callers
    naturally fall outside it:

    * ``python -m web3_secops.main`` sets ``__name__ == "__main__"``
    * a stray ``get_logger("probe")`` from user code or a script

    Both would silently emit nothing, which is the worst failure mode for a
    collector: it looks like it ran and found nothing. Names are therefore
    normalised into the tree — ``__main__`` becomes ``web3_secops.__main__`` and
    a bare ``probe`` becomes ``web3_secops.probe`` — so a record can never be
    dropped just because of how the module was invoked.
    """
    if _handler is None:
        configure_logging(os.environ.get("LOG_LEVEL", "INFO"))

    if name == "web3_secops" or name.startswith("web3_secops."):
        qualified = name
    elif name == "__main__":
        qualified = "web3_secops.__main__"
    else:
        qualified = f"web3_secops.{name}"

    return StructuredLogger(logging.getLogger(qualified))
