"""Entry point (M1-C).

Modes
-----
``--check-rpc``  connect, verify chain id and report the current head. No writes.
``--once``       scan one batch of confirmed blocks, then exit.
``--watch``      scan forever, sleeping ``POLL_INTERVAL_SECONDS`` between batches.

A bare ``python -m web3_secops.main`` prints usage and exits: it never starts an
infinite loop implicitly, so an accidental invocation in a terminal or a CI job
cannot hang.

JSON Lines logging: one object per line on stdout with ``timestamp``, ``level``
and ``event`` always present, plus ``chain_id`` / ``block_number`` /
``duration_ms`` where they apply.

What this stage does NOT do: it does not detect attacks, does not decode ERC-20
events, and does not emit security alerts. It collects blocks and records scan
state. Calling anything else a "security alert" would be dishonest.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Sequence

from .block_scanner import (
    BlockScanner,
    ReorgOutOfWindowError,
    ScannerError,
    StateStore,
)
from .config import ConfigError, Settings, load_settings
from .logging_setup import configure_logging, get_logger
from .rpc_client import RpcClient, RpcError

log = get_logger(__name__)

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_RPC = 3
EXIT_SCANNER = 4
EXIT_INTERRUPTED = 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web3-secops",
        description=(
            "Read-only Ethereum block collector. One of --check-rpc, --once or --watch is required."
        ),
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--check-rpc",
        action="store_true",
        help="verify RPC connectivity, chain id and current head, then exit",
    )
    mode.add_argument(
        "--once",
        action="store_true",
        help="scan one batch of confirmed blocks, then exit",
    )
    mode.add_argument(
        "--watch",
        action="store_true",
        help="scan continuously, polling at POLL_INTERVAL_SECONDS",
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="path to an env file (default: .env; pass '' to skip)",
    )
    return parser


def _make_client(settings: Settings) -> RpcClient:
    url, _ = settings.require_rpc()
    return RpcClient(
        url=url,
        timeout=settings.rpc_timeout_seconds,
        max_retries=settings.rpc_max_retries,
    )


def _make_scanner(settings: Settings, client: RpcClient, chain_id: int) -> BlockScanner:
    store = StateStore(settings.state_db_path, chain_id)
    return BlockScanner(client, store, config=settings.scanner)


def run_check_rpc(settings: Settings) -> int:
    """Verify the RPC endpoint. Read-only: two calls, no persistence."""
    started = time.monotonic()
    with _make_client(settings) as client:
        chain_id = client.get_chain_id()
        head = client.get_block_number()
        duration_ms = round((time.monotonic() - started) * 1000)

        expected = settings.expected_chain_id
        matches = expected is None or chain_id == expected

        # A chain-id mismatch means we are talking to the wrong network, which
        # is a setup error, not a successful check. Logging it at INFO made a
        # misconfigured run look identical to a healthy one.
        log_fn = log.info if matches else log.error
        log_fn(
            "rpc_check_ok" if matches else "rpc_check_chain_mismatch",
            chain_id=chain_id,
            expected_chain_id=expected,
            block_number=head,
            endpoint=client.endpoint,
            duration_ms=duration_ms,
        )

        if not matches:
            return EXIT_CONFIG
    return EXIT_OK


def run_once(settings: Settings) -> int:
    """Scan one batch and exit."""
    started = time.monotonic()
    with _make_client(settings) as client:
        _, expected_chain_id = settings.require_rpc()
        scanner = _make_scanner(settings, client, expected_chain_id)
        try:
            actual = scanner.verify_chain_id(expected_chain_id)
            log.info("chain_id_verified", chain_id=actual, expected_chain_id=expected_chain_id)

            result = scanner.scan_once()
            duration_ms = round((time.monotonic() - started) * 1000)
            log.info(
                "scan_once_finished",
                chain_id=actual,
                block_number=result.last_block,
                first_block=result.first_block,
                blocks_scanned=result.blocks_scanned,
                head=result.head,
                safe_head=result.safe_head,
                reorg_rollback_to=result.reorg_rollback_to,
                caught_up=result.caught_up,
                duration_ms=duration_ms,
            )
        finally:
            scanner.store.close()
    return EXIT_OK


def run_watch(settings: Settings) -> int:
    """Scan continuously. Ctrl-C exits cleanly."""
    _, expected_chain_id = settings.require_rpc()
    interval = settings.scanner.poll_interval_seconds
    processed = 0

    with _make_client(settings) as client:
        scanner = _make_scanner(settings, client, expected_chain_id)
        try:
            actual = scanner.verify_chain_id(expected_chain_id)
            log.info(
                "watch_started",
                chain_id=actual,
                poll_interval_seconds=interval,
                confirmations=settings.scanner.confirmations,
                batch_size=settings.scanner.block_batch_size,
                reorg_window=settings.scanner.reorg_window,
            )
            while True:
                started = time.monotonic()
                result = scanner.scan_once()
                processed += result.blocks_scanned
                log.info(
                    "watch_iteration",
                    chain_id=actual,
                    block_number=result.last_block,
                    blocks_scanned=result.blocks_scanned,
                    blocks_total=processed,
                    head=result.head,
                    safe_head=result.safe_head,
                    caught_up=result.caught_up,
                    duration_ms=round((time.monotonic() - started) * 1000),
                )
                time.sleep(interval)
        finally:
            scanner.store.close()
    return EXIT_OK  # pragma: no cover - loop exits via exception


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        settings = load_settings(args.env_file or None)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    configure_logging(settings.log_level)
    log.info(
        "startup",
        log_level=settings.log_level,
        endpoint=settings.safe_rpc_url,
        state_db_path=settings.state_db_path,
        mode="check-rpc" if args.check_rpc else ("once" if args.once else "watch"),
    )

    try:
        if args.check_rpc:
            return run_check_rpc(settings)
        if args.once:
            return run_once(settings)
        return run_watch(settings)
    except ConfigError as exc:
        log.error("config_error", reason=str(exc))
        return EXIT_CONFIG
    except ReorgOutOfWindowError as exc:
        # Deliberately fatal: guessing here would corrupt the scan history.
        log.critical("reorg_out_of_window", reason=str(exc))
        return EXIT_SCANNER
    except ScannerError as exc:
        log.error("scanner_error", reason=str(exc))
        return EXIT_SCANNER
    except RpcError as exc:
        log.error("rpc_error", reason=str(exc))
        return EXIT_RPC
    except KeyboardInterrupt:
        log.info("shutdown", status="interrupted")
        return EXIT_INTERRUPTED


if __name__ == "__main__":  # pragma: no cover
    try:
        code = main()
    finally:
        # Flush explicitly: when stdout is a pipe (CI, `| tee`, subprocess
        # capture) Python buffers it, and os._exit-style termination or an
        # unflushed interpreter shutdown would drop the trailing log records.
        sys.stdout.flush()
        sys.stderr.flush()
    sys.exit(code)
