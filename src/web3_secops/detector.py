"""Detection rules over normalised blocks and decoded events.

Each rule is a small callable that inspects activity and returns zero or more
:class:`Finding` objects. Findings carry a severity and structured context so
downstream sinks (file, webhook, Wazuh) can route them.

The detector is intentionally rule-based and transparent — no ML, no magic.
Add a rule by writing a function and registering it in ``DEFAULT_RULES``.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

import structlog

from .block_scanner import NormalizedBlock, NormalizedTx

log = structlog.get_logger(__name__)

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# ERC-20 Transfer topic0 (precomputed to avoid keccak dependency at runtime)
ERC20_TRANSFER_TOPIC = (
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
)


@dataclass(slots=True)
class Finding:
    rule: str
    severity: str
    title: str
    description: str
    context: dict[str, Any] = field(default_factory=dict)
    chain_id: int | None = None
    block_number: int | None = None
    tx_hash: str | None = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "chain_id": self.chain_id,
            "block_number": self.block_number,
            "tx_hash": self.tx_hash,
            "timestamp": self.timestamp,
            "context": self.context,
        }


@dataclass(slots=True)
class WatchEntry:
    address: str
    label: str
    severity: str = "high"
    tags: list[str] = field(default_factory=list)
    watch_inbound: bool = True
    watch_outbound: bool = True


@dataclass(slots=True)
class DetectorConfig:
    watched: dict[str, WatchEntry] = field(default_factory=dict)
    flagged_contracts: dict[str, dict[str, Any]] = field(default_factory=dict)
    min_notable_value: float = 10.0
    rapid_drain_count: int = 3
    rapid_drain_window_seconds: int = 300
    chain_id: int | None = None


class Detector:
    """Apply detection rules to blocks and decoded events.

    Example
    -------
    >>> det = Detector(DetectorConfig(watched={"0xabc": WatchEntry("0xabc", "Treasury")}))
    >>> findings = det.inspect_block(block)
    """

    def __init__(self, config: DetectorConfig):
        self.config = config
        self._outbound: dict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=config.rapid_drain_count * 4)
        )

    # -- rule: watched address touched ------------------------------------
    def _rule_watched_address(self, tx: NormalizedTx, block: NormalizedBlock) -> list[Finding]:
        out: list[Finding] = []
        frm = tx.from_addr.lower()
        to = (tx.to_addr or "").lower()

        if frm in self.config.watched:
            entry = self.config.watched[frm]
            self._outbound[frm].append(block.timestamp)
            if entry.watch_outbound:
                recent = self._recent_outbound(frm, block.timestamp)
                if recent >= self.config.rapid_drain_count:
                    out.append(
                        Finding(
                            rule="rapid-drain",
                            severity="critical",
                            title=f"Rapid outbound drain from {entry.label}",
                            description=(
                                f"{recent} outbound txs from {entry.label} within "
                                f"{self.config.rapid_drain_window_seconds}s"
                            ),
                            context={"address": frm, "label": entry.label,
                                     "count": recent, "tags": entry.tags},
                            chain_id=self.config.chain_id,
                            block_number=block.number,
                            tx_hash=tx.hash,
                        )
                    )
                out.append(
                    Finding(
                        rule="watched-outbound",
                        severity=entry.severity,
                        title=f"Outbound tx from {entry.label}",
                        description=(
                            f"{entry.label} sent {tx.value_native:.4f} native in tx {tx.hash}"
                        ),
                        context={"address": frm, "label": entry.label,
                                 "to": to, "value_native": tx.value_native,
                                 "tags": entry.tags},
                        chain_id=self.config.chain_id,
                        block_number=block.number,
                        tx_hash=tx.hash,
                    )
                )

        if to in self.config.watched:
            entry = self.config.watched[to]
            if entry.watch_inbound:
                out.append(
                    Finding(
                        rule="watched-inbound",
                        severity=entry.severity,
                        title=f"Inbound tx to {entry.label}",
                        description=(
                            f"{entry.label} received {tx.value_native:.4f} native in tx {tx.hash}"
                        ),
                        context={"address": to, "label": entry.label,
                                 "from": frm, "value_native": tx.value_native,
                                 "tags": entry.tags},
                        chain_id=self.config.chain_id,
                        block_number=block.number,
                        tx_hash=tx.hash,
                    )
                )
        return out

    def _recent_outbound(self, addr: str, now_ts: int) -> int:
        window = self.config.rapid_drain_window_seconds
        return sum(1 for ts in self._outbound[addr] if now_ts - ts <= window)

    # -- rule: large native transfer --------------------------------------
    def _rule_large_transfer(self, tx: NormalizedTx, block: NormalizedBlock) -> list[Finding]:
        if tx.value_native < self.config.min_notable_value:
            return []
        return [
            Finding(
                rule="large-transfer",
                severity="medium",
                title="Large native transfer",
                description=(
                    f"{tx.value_native:.4f} native moved in tx {tx.hash}"
                ),
                context={"from": tx.from_addr, "to": tx.to_addr,
                         "value_native": tx.value_native},
                chain_id=self.config.chain_id,
                block_number=block.number,
                tx_hash=tx.hash,
            )
        ]

    # -- rule: interaction with flagged contract --------------------------
    def _rule_flagged_contract(
        self, tx: NormalizedTx, block: NormalizedBlock
    ) -> list[Finding]:
        if not self.config.flagged_contracts:
            return []
        to = (tx.to_addr or "").lower()
        entry = self.config.flagged_contracts.get(to)
        if not entry:
            return []
        return [
            Finding(
                rule="flagged-interaction",
                severity=entry.get("severity", "high"),
                title=f"Interaction with flagged contract: {entry.get('label', to)}",
                description=(
                    f"tx {tx.hash} interacted with flagged contract {to} "
                    f"({entry.get('reason', 'n/a')})"
                ),
                context={"contract": to, "label": entry.get("label"),
                         "reason": entry.get("reason"), "from": tx.from_addr},
                chain_id=self.config.chain_id,
                block_number=block.number,
                tx_hash=tx.hash,
            )
        ]

    # -- orchestration ----------------------------------------------------
    def inspect_tx(self, tx: NormalizedTx, block: NormalizedBlock) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._rule_watched_address(tx, block)
        findings += self._rule_large_transfer(tx, block)
        findings += self._rule_flagged_contract(tx, block)
        return findings

    def inspect_block(self, block: NormalizedBlock) -> list[Finding]:
        findings: list[Finding] = []
        for tx in block.transactions:
            findings += self.inspect_tx(tx, block)
        return findings

    def inspect_event(self, decoded: dict[str, Any]) -> list[Finding]:
        """Rules over decoded contract events (e.g. ERC-20 Transfer)."""
        findings: list[Finding] = []
        raw = decoded.get("raw", {})
        if decoded.get("event") == "Transfer":
            args = decoded.get("args", {})
            frm = str(args.get("from", "")).lower()
            to = str(args.get("to", "")).lower()
            for addr, direction in ((frm, "from"), (to, "to")):
                if addr in self.config.watched:
                    entry = self.config.watched[addr]
                    findings.append(
                        Finding(
                            rule="token-movement",
                            severity=entry.severity,
                            title=f"Token movement {'from' if direction=='from' else 'to'} {entry.label}",
                            description=(
                                f"{entry.label} involved in Transfer event "
                                f"(log {raw.get('log_index')})"
                            ),
                            context={"address": addr, "label": entry.label,
                                     "args": args, "tags": entry.tags},
                            chain_id=self.config.chain_id,
                            block_number=raw.get("block_number"),
                            tx_hash=raw.get("tx_hash"),
                        )
                    )
        return findings


def filter_by_severity(findings: Iterable[Finding], min_severity: str) -> list[Finding]:
    threshold = SEVERITY_ORDER.get(min_severity, 0)
    return [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= threshold]


# Registry seam for custom rules (populate from plugins if desired)
DEFAULT_RULES: list[Callable[..., list[Finding]]] = [
    Detector._rule_watched_address,
    Detector._rule_large_transfer,
    Detector._rule_flagged_contract,
]
