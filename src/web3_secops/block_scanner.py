"""Block iteration with persistent cursor + dedup.

The scanner walks the chain one block at a time (or in small batches), yielding
normalised block records. A SQLite-backed cursor lets it resume exactly where it
left off after a restart, and a bounded dedup set prevents emitting the same
block twice when the chain reorgs near the tip.

Read-only: this module only calls ``eth_blockNumber`` and
``eth_getBlockByNumber``.
"""

from __future__ import annotations

import json
import sqlite3
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import structlog

from .rpc_client import RpcClient

log = structlog.get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cursor (
    chain_id   INTEGER PRIMARY KEY,
    last_block INTEGER NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS seen_blocks (
    chain_id INTEGER NOT NULL,
    number   INTEGER NOT NULL,
    hash     TEXT NOT NULL,
    PRIMARY KEY (chain_id, number)
);
"""


@dataclass(slots=True)
class NormalizedTx:
    """A transaction reduced to the fields detection cares about."""

    hash: str
    from_addr: str
    to_addr: str | None
    value_wei: int
    block_number: int
    tx_index: int

    @property
    def value_native(self) -> float:
        return self.value_wei / 1e18


@dataclass(slots=True)
class NormalizedBlock:
    """A block reduced to the fields detection cares about."""

    number: int
    hash: str
    parent_hash: str
    timestamp: int
    transactions: list[NormalizedTx]


class CursorStore:
    """Durable scan cursor + recent-block dedup, backed by SQLite."""

    def __init__(self, db_path: str | Path, chain_id: int, dedup_window: int = 64):
        self.db_path = Path(db_path)
        self.chain_id = chain_id
        self.dedup_window = dedup_window
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def get_last_block(self) -> int | None:
        row = self._conn.execute(
            "SELECT last_block FROM cursor WHERE chain_id = ?", (self.chain_id,)
        ).fetchone()
        return int(row[0]) if row else None

    def set_last_block(self, block: int) -> None:
        self._conn.execute(
            """INSERT INTO cursor (chain_id, last_block, updated_at)
               VALUES (?, ?, datetime('now'))
               ON CONFLICT(chain_id) DO UPDATE
                 SET last_block = excluded.last_block,
                     updated_at = excluded.updated_at""",
            (self.chain_id, block),
        )
        # Trim dedup table to the window
        self._conn.execute(
            """DELETE FROM seen_blocks
               WHERE chain_id = ? AND number < ?""",
            (self.chain_id, block - self.dedup_window),
        )
        self._conn.commit()

    def is_seen(self, number: int, block_hash: str) -> bool:
        row = self._conn.execute(
            "SELECT hash FROM seen_blocks WHERE chain_id = ? AND number = ?",
            (self.chain_id, number),
        ).fetchone()
        return bool(row and row[0] == block_hash)

    def mark_seen(self, number: int, block_hash: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO seen_blocks (chain_id, number, hash) VALUES (?, ?, ?)",
            (self.chain_id, number, block_hash),
        )
        self._conn.commit()


def _normalize_block(raw: dict[str, Any], full_tx: bool) -> NormalizedBlock:
    txs: list[NormalizedTx] = []
    for idx, tx in enumerate(raw.get("transactions", [])):
        if not full_tx:
            continue
        txs.append(
            NormalizedTx(
                hash=tx["hash"],
                from_addr=tx["from"],
                to_addr=tx.get("to"),
                value_wei=int(tx.get("value", "0x0"), 16),
                block_number=int(raw["number"], 16),
                tx_index=idx,
            )
        )
    return NormalizedBlock(
        number=int(raw["number"], 16),
        hash=raw["hash"],
        parent_hash=raw.get("parentHash", ""),
        timestamp=int(raw.get("timestamp", "0x0"), 16),
        transactions=txs,
    )


class BlockScanner:
    """Iterate new blocks, resuming from a durable cursor.

    Example
    -------
    >>> scanner = BlockScanner(client, CursorStore("state.db", chain_id=1), chain_id=1)
    >>> for block in scanner.stream():
    ...     process(block)
    """

    def __init__(
        self,
        client: RpcClient,
        store: CursorStore,
        chain_id: int,
        lookback: int = 100,
        batch_size: int = 1,
        confirmations: int = 1,
    ):
        self.client = client
        self.store = store
        self.chain_id = chain_id
        self.lookback = lookback
        self.batch_size = max(1, batch_size)
        self.confirmations = max(0, confirmations)

    def _cold_start(self) -> int:
        head = self.client.get_block_number()
        return max(0, head - self.lookback)

    def stream(self, max_blocks: int | None = None) -> Iterator[NormalizedBlock]:
        """Yield normalised blocks in order. Stops after ``max_blocks`` if set."""
        cursor = self.store.get_last_block()
        start = (cursor + 1) if cursor is not None else self._cold_start()
        emitted = 0
        recent: deque[int] = deque(maxlen=self.batch_size * 2)

        while max_blocks is None or emitted < max_blocks:
            head = self.client.get_block_number() - self.confirmations
            if start > head:
                return  # caught up

            end = min(start + self.batch_size - 1, head)
            for number in range(start, end + 1):
                raw = self.client.get_block(number, full_tx=True)
                if raw is None:  # reorg / pruned — skip and retry next round
                    log.warning("block_missing", number=number)
                    continue

                block = _normalize_block(raw, full_tx=True)
                if self.store.is_seen(block.number, block.hash):
                    log.debug("block_duplicate", number=block.number)
                    continue

                self.store.mark_seen(block.number, block.hash)
                self.store.set_last_block(block.number)
                recent.append(block.number)
                emitted += 1
                yield block

            start = end + 1

    def head(self) -> int:
        return self.client.get_block_number()

    def to_json(self, block: NormalizedBlock) -> str:
        return json.dumps(
            {
                "number": block.number,
                "hash": block.hash,
                "timestamp": block.timestamp,
                "tx_count": len(block.transactions),
            }
        )
