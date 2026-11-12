"""Environment configuration (M1-C).

Configuration precedence, highest first:

1. real process environment variables
2. values from a ``.env`` file in the working directory (loaded by python-dotenv)
3. defaults defined here

The RPC URL frequently contains an API key. It is therefore *never* logged in
raw form and never written to the database; :meth:`Settings.safe_rpc_url`
returns a redacted version for logging.

No real key belongs in ``.env.example`` or in git. ``.env`` is git-ignored.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

from .block_scanner import ScannerConfig
from .rpc_client import redact_url

_DEFAULT_ENV_FILE = ".env"
_VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


class ConfigError(ValueError):
    """A configuration value is missing or malformed."""


def _env_str(name: str, default: str | None) -> str | None:
    raw = os.environ.get(name)
    if raw is None:
        return default
    raw = raw.strip()
    return raw if raw else default


def _env_int(name: str, default: int | None, *, minimum: int | None = None) -> int | None:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        value = default
    else:
        try:
            value = int(raw.strip())
        except ValueError as exc:
            raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if value is not None and minimum is not None and value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    return value


def _env_float(name: str, default: float, *, minimum: float | None = None) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        value = default
    else:
        try:
            value = float(raw.strip())
        except ValueError as exc:
            raise ConfigError(f"{name} must be a number, got {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable, validated application configuration."""

    rpc_url: str | None
    expected_chain_id: int | None
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    state_db_path: str = "./data/state.db"
    log_level: str = "INFO"
    rpc_timeout_seconds: float = 20.0
    rpc_max_retries: int = 3

    # -- logging safety ----------------------------------------------------
    @property
    def safe_rpc_url(self) -> str:
        """RPC URL with any key material stripped, for logs."""
        return redact_url(self.rpc_url) if self.rpc_url else "<unset>"

    @property
    def rpc_configured(self) -> bool:
        return bool(self.rpc_url)

    def require_rpc(self) -> tuple[str, int]:
        """Return ``(rpc_url, expected_chain_id)`` or raise a clear ConfigError.

        Called by entry points that need the network, so ``--help`` and offline
        tooling still work without an RPC URL.
        """
        missing = []
        if not self.rpc_url:
            missing.append("ETHEREUM_RPC_URL")
        if self.expected_chain_id is None:
            missing.append("EXPECTED_CHAIN_ID")
        if missing:
            raise ConfigError(
                "missing required configuration: "
                + ", ".join(missing)
                + " — copy .env.example to .env and fill them in"
            )
        assert self.rpc_url is not None  # narrowed by the check above
        assert self.expected_chain_id is not None
        return self.rpc_url, self.expected_chain_id


def load_settings(env_file: str | Path | None = _DEFAULT_ENV_FILE) -> Settings:
    """Read configuration from the environment, optionally loading a .env file."""
    if env_file is not None:
        path = Path(env_file)
        if path.is_file():
            load_dotenv(path, override=False)

    log_level = (_env_str("LOG_LEVEL", "INFO") or "INFO").upper()
    if log_level not in _VALID_LOG_LEVELS:
        raise ConfigError(
            f"LOG_LEVEL must be one of {sorted(_VALID_LOG_LEVELS)}, got {log_level!r}"
        )

    scanner = ScannerConfig(
        confirmations=_env_int("CONFIRMATIONS", 12, minimum=0) or 0,
        block_batch_size=_env_int("BLOCK_BATCH_SIZE", 5, minimum=1) or 5,
        reorg_window=_env_int("REORG_WINDOW", 64, minimum=1) or 64,
        start_block_lookback=_env_int("START_BLOCK_LOOKBACK", 20, minimum=0) or 0,
        start_block=_env_int("START_BLOCK", None, minimum=0),
        poll_interval_seconds=_env_float("POLL_INTERVAL_SECONDS", 12.0, minimum=0.001),
    )

    rpc_url = _env_str("ETHEREUM_RPC_URL", None)
    if rpc_url is not None and not rpc_url.lower().startswith(("http://", "https://")):
        raise ConfigError("ETHEREUM_RPC_URL must start with http:// or https://")

    return Settings(
        rpc_url=rpc_url,
        expected_chain_id=_env_int("EXPECTED_CHAIN_ID", None, minimum=1),
        scanner=scanner,
        state_db_path=_env_str("STATE_DB_PATH", "./data/state.db") or "./data/state.db",
        log_level=log_level,
        rpc_timeout_seconds=_env_float("RPC_TIMEOUT_SECONDS", 20.0, minimum=0.1),
        rpc_max_retries=_env_int("RPC_MAX_RETRIES", 3, minimum=0) or 0,
    )
