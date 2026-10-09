"""Entry point: wire config -> scanner -> decoder -> detector -> alert sink.

Read-only by design: this loop never signs or broadcasts anything.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

import structlog
import yaml
from dotenv import load_dotenv

from .block_scanner import BlockScanner, CursorStore
from .detector import Detector, DetectorConfig, Finding, WatchEntry, filter_by_severity
from .event_decoder import EventDecoder, RawLog
from .rpc_client import RpcClient

load_dotenv()
log = structlog.get_logger("web3_secops")

_RUNNING = True


def _handle_signal(signum: int, _frame: Any) -> None:
    global _RUNNING
    log.info("shutdown_requested", signal=signum)
    _RUNNING = False


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------
def load_watchlist(path: str | Path) -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text()) or {}


def build_detector_config(watchlist: dict[str, Any], chain_id: int | None) -> DetectorConfig:
    watched: dict[str, WatchEntry] = {}
    for entry in watchlist.get("addresses", []) or []:
        addr = entry["address"].lower()
        watched[addr] = WatchEntry(
            address=addr,
            label=entry.get("label", addr),
            severity=entry.get("severity", "high"),
            tags=entry.get("tags", []) or [],
            watch_inbound=entry.get("watch_inbound", True),
            watch_outbound=entry.get("watch_outbound", True),
        )

    flagged = {
        c["address"].lower(): {
            "label": c.get("label", c["address"]),
            "reason": c.get("reason", ""),
            "severity": c.get("severity", "high"),
        }
        for c in (watchlist.get("flagged_contracts", []) or [])
    }

    thresholds = watchlist.get("thresholds", {}) or {}
    return DetectorConfig(
        watched=watched,
        flagged_contracts=flagged,
        min_notable_value=float(
            thresholds.get("min_notable_value", os.getenv("MIN_NOTABLE_VALUE", 10))
        ),
        rapid_drain_count=int(thresholds.get("rapid_drain_count", 3)),
        rapid_drain_window_seconds=int(thresholds.get("rapid_drain_window_seconds", 300)),
        chain_id=chain_id,
    )


def build_event_decoder(watchlist: dict[str, Any]) -> EventDecoder:
    decoder = EventDecoder()
    for contract in watchlist.get("contracts", []) or []:
        abi = contract.get("abi")
        if abi and Path(abi).exists():
            n = decoder.register_from_abi_file(abi)
            log.info("abi_loaded", contract=contract.get("label"), events=n)
    return decoder


# ---------------------------------------------------------------------------
# Alert sink
# ---------------------------------------------------------------------------
class AlertSink:
    """Append findings as JSON lines; Wazuh agent tails this file."""

    def __init__(self, path: str | Path, min_severity: str = "low"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.min_severity = min_severity

    def emit(self, findings: list[Finding]) -> int:
        kept = filter_by_severity(findings, self.min_severity)
        if not kept:
            return 0
        with self.path.open("a", encoding="utf-8") as fh:
            for f in kept:
                fh.write(json.dumps(f.to_dict()) + "\n")
                log.info("alert", rule=f.rule, severity=f.severity, title=f.title)
        return len(kept)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
def run(args: argparse.Namespace) -> int:
    watchlist = load_watchlist(args.watchlist)
    chain_name = args.chain
    chains = {c["name"]: c for c in watchlist.get("chains", []) or []}
    if chain_name not in chains:
        log.error("unknown_chain", chain=chain_name, available=list(chains))
        return 2

    chain = chains[chain_name]
    chain_id = int(chain["chain_id"])
    rpc_url = os.getenv(chain.get("rpc_env", ""), "")
    if not rpc_url:
        log.error("rpc_url_missing", env=chain.get("rpc_env"))
        return 2

    client = RpcClient(rpc_url, chain_id=chain_id)
    store = CursorStore(
        os.getenv("STATE_DB_PATH", "./data/state.db"),
        chain_id=chain_id,
    )
    scanner = BlockScanner(
        client,
        store,
        chain_id=chain_id,
        lookback=int(os.getenv("START_BLOCK_LOOKBACK", 100)),
        batch_size=int(os.getenv("BLOCK_BATCH_SIZE", 5)),
    )
    detector = Detector(build_detector_config(watchlist, chain_id))
    decoder = build_event_decoder(watchlist)
    alerts_cfg = watchlist.get("alerts", {}) or {}
    sink = AlertSink(
        alerts_cfg.get("file_path", os.getenv("ALERT_LOG_PATH", "./logs/alerts.jsonl")),
        min_severity=alerts_cfg.get("min_severity", "low"),
    )

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    poll = int(os.getenv("POLL_INTERVAL_SECONDS", 12))
    log.info("starting", chain=chain_name, chain_id=chain_id,
             head=scanner.head(), watchlist=args.watchlist)

    global _RUNNING
    while _RUNNING:
        emitted = 0
        for block in scanner.stream(max_blocks=args.max_blocks):
            findings = detector.inspect_block(block)

            # Decode events for contracts in the watchlist, then rule on them
            contract_addrs = [
                c["address"].lower() for c in (watchlist.get("contracts", []) or [])
            ]
            if contract_addrs and block.transactions:
                logs = client.get_logs(block.number, block.number, address=contract_addrs)
                for entry in logs:
                    decoded = decoder.decode(RawLog.from_rpc(entry))
                    if decoded:
                        findings += detector.inspect_event(decoded)

            emitted += sink.emit(findings)
            log.info("block_scanned", number=block.number,
                     txs=len(block.transactions), alerts=len(findings))

        if args.once:
            break
        log.debug("sleeping", seconds=poll)
        for _ in range(poll):
            if not _RUNNING:
                break
            time.sleep(1)

    client.close()
    store.close()
    log.info("stopped")
    return 0


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="web3-secops",
        description="Web3 SecOps Lab — read-only on-chain security monitor",
    )
    parser.add_argument(
        "--watchlist", default="config/watchlist.yaml",
        help="Path to watchlist YAML (default: config/watchlist.yaml)",
    )
    parser.add_argument(
        "--chain", default="ethereum",
        help="Chain name from the watchlist (default: ethereum)",
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Scan once and exit (useful for tests / cron)",
    )
    parser.add_argument(
        "--max-blocks", type=int, default=None,
        help="Stop after scanning N blocks (default: run continuously)",
    )
    parser.add_argument("--verbose", action="store_true", help="DEBUG logging")
    args = parser.parse_args(argv)

    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(
            10 if args.verbose else 20
        )
    )
    return run(args)


if __name__ == "__main__":
    sys.exit(cli())
