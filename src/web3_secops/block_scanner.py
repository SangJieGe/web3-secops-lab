"""Block scanner with durable cursor and reorg handling (M1-B).

What this module does
---------------------
It walks the chain forward from a persisted cursor, one confirmed block at a
time, and hands each block to the caller. Three properties matter:

1. **Crash safety.** The cursor and the block row are written in the *same*
   SQLite transaction. There is no interleaving in which the cursor advances
   but its block is missing. A process killed between batches resumes at the
   last committed block.

2. **Reorg awareness.** The last ``reorg_window`` block hashes are retained. On
   the next block, the parent hash must equal the stored hash of the previous
   block. A mismatch means the chain we recorded is no longer canonical, so we
   locate the common ancestor inside the window, roll the cursor back to it,
   and rescan forward. If no common ancestor exists inside the window we refuse
   to guess: :class:`ReorgOutOfWindowError` is raised and scanning stops.

3. **Idempotency.** Re-scanning a block whose hash is unchanged is a no-op; a
   block whose hash *changed* replaces the stored row. The unique key is
   ``(chain_id, block_number)``, so duplicate inserts cannot accumulate.

Chain isolation
---------------
Every row carries ``chain_id`` and every query filters on it. Two chains sharing
one database file cannot see or disturb each other's state.

Read-only
---------
The only RPC methods used are ``eth_blockNumber`` and ``eth_getBlockByNumber``,
both enforced by :mod:`web3_secops.rpc_client`'s allowlist.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any

from .logging_setup import get_logger
from .rpc_client import NormalizedBlock, RpcClient

log = get_logger(__name__)

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_state (
    chain_id    INTEGER PRIMARY KEY,
    last_block  INTEGER NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blocks (
    chain_id     INTEGER NOT NULL,
    block_number INTEGER NOT NULL,
    block_hash   TEXT    NOT NULL,
    parent_hash  TEXT    NOT NULL,
    timestamp    INTEGER NOT NULL,
    tx_count     INTEGER NOT NULL,
    scanned_at   TEXT    NOT NULL,
    PRIMARY KEY (chain_id, block_number)
);

CREATE INDEX IF NOT EXISTS idx_blocks_hash
    ON blocks (chain_id, block_hash);
"""


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class ScannerError(RuntimeError):
    """Base class for scanner failures."""


class ReorgOutOfWindowError(ScannerError):
    """A reorg was detected but no common ancestor exists inside the window.

    Raised instead of silently rescanning from an arbitrary block, because
    guessing here would mean permanently missing history we can no longer
    verify.
    """


class ParentHashMismatchError(ScannerError):
    """The parent hash of a block does not match the previously stored block."""


# ---------------------------------------------------------------------------
# Domain
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class StoredBlock:
    """A block as persisted in the local database."""

    chain_id: int
    block_number: int
    block_hash: str
    parent_hash: str
    timestamp: int
    tx_count: int
    scanned_at: str


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Outcome of one :meth:`BlockScanner.scan_once` call."""

    blocks_scanned: int
    first_block: int | None
    last_block: int | None
    head: int
    safe_head: int
    reorg_rollback_to: int | None = None
    caught_up: bool = False


@dataclass(frozen=True, slots=True)
class ScannerConfig:
    """Scanner tunables. Defaults mirror ``.env.example``."""

    confirmations: int = 12
    block_batch_size: int = 5
    reorg_window: int = 64
    start_block_lookback: int = 20
    start_block: int | None = None
    poll_interval_seconds: float = 12.0

    def __post_init__(self) -> None:
        if self.confirmations < 0:
            raise ValueError("confirmations must be >= 0")
        if self.block_batch_size < 1:
            raise ValueError("block_batch_size must be >= 1")
        if self.reorg_window < 1:
            raise ValueError("reorg_window must be >= 1")
        if self.start_block_lookback < 0:
            raise ValueError("start_block_lookback must be >= 0")
        if self.start_block is not None and self.start_block < 0:
            raise ValueError("start_block must be >= 0")
        if self.poll_interval_seconds <= 0:
            raise ValueError("poll_interval_seconds must be > 0")


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
class StateStore:
    """SQLite-backed scan state. Enforces chain isolation and atomic writes."""

    def __init__(self, db_path: str | Path, chain_id: int, retain_blocks: int = 0) -> None:
        if not isinstance(chain_id, int) or chain_id <= 0:
            raise ValueError("chain_id must be a positive integer")

        self.db_path = Path(db_path)
        self.chain_id = chain_id
        # How many blocks below the cursor to keep. 0 means "keep everything",
        # which is the safe default for a store used on its own. BlockScanner
        # sets this to REORG_WINDOW so long-running scans stay bounded.
        self.retain_blocks = max(0, retain_blocks)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        is_new = not self.db_path.exists()
        self._conn = sqlite3.connect(self.db_path, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(_SCHEMA)
        self._initialise_meta()

        if is_new:
            self._restrict_permissions()

    # -- setup -------------------------------------------------------------
    def _initialise_meta(self) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO schema_meta (key, value) VALUES (?, ?)",
            ("schema_version", str(SCHEMA_VERSION)),
        )

    def _restrict_permissions(self) -> None:
        """Make the DB owner-readable only.

        The scan state itself is not secret, but it lives next to configuration
        and a world-readable DB is an unnecessary exposure on a shared host.
        Best-effort: on Windows or an exotic filesystem this may be a no-op.
        """
        for suffix in ("", "-wal", "-shm"):
            target = Path(str(self.db_path) + suffix)
            try:
                if target.exists():
                    os.chmod(target, 0o600)
            except OSError:  # pragma: no cover - platform dependent
                log.debug("db_chmod_skipped", path=str(target))

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> StateStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- reads -------------------------------------------------------------
    def get_last_block(self) -> int | None:
        """Last fully committed block for *this* chain, or None if never run."""
        row = self._conn.execute(
            "SELECT last_block FROM scan_state WHERE chain_id = ?",
            (self.chain_id,),
        ).fetchone()
        return int(row["last_block"]) if row else None

    def get_block(self, block_number: int) -> StoredBlock | None:
        row = self._conn.execute(
            "SELECT * FROM blocks WHERE chain_id = ? AND block_number = ?",
            (self.chain_id, block_number),
        ).fetchone()
        return _row_to_block(row) if row else None

    def recent_hashes(self, limit: int) -> list[StoredBlock]:
        """Most recent ``limit`` stored blocks, oldest first."""
        rows = self._conn.execute(
            "SELECT * FROM blocks WHERE chain_id = ? ORDER BY block_number DESC LIMIT ?",
            (self.chain_id, limit),
        ).fetchall()
        return [_row_to_block(row) for row in reversed(rows)]

    def block_count(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS c FROM blocks WHERE chain_id = ?", (self.chain_id,)
        ).fetchone()
        return int(row["c"])

    # -- atomic writes -----------------------------------------------------
    def commit_block(self, block: NormalizedBlock) -> bool:
        """Persist a block and advance the cursor in one transaction.

        Returns True if a new row was inserted, False if an existing row with an
        identical hash was left untouched.

        The block row and the cursor row are written inside a single
        ``BEGIN IMMEDIATE`` transaction, so a crash cannot leave the cursor
        pointing past a block that was never stored.
        """
        now = _utc_now_iso()
        existing = self.get_block(block.number)

        if existing is not None and existing.block_hash == block.hash:
            return False

        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                """
                INSERT INTO blocks (
                    chain_id, block_number, block_hash, parent_hash,
                    timestamp, tx_count, scanned_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain_id, block_number) DO UPDATE SET
                    block_hash  = excluded.block_hash,
                    parent_hash = excluded.parent_hash,
                    timestamp   = excluded.timestamp,
                    tx_count    = excluded.tx_count,
                    scanned_at  = excluded.scanned_at
                """,
                (
                    self.chain_id,
                    block.number,
                    block.hash,
                    block.parent_hash,
                    block.timestamp,
                    len(block.transactions),
                    now,
                ),
            )
            self._conn.execute(
                """
                INSERT INTO scan_state (chain_id, last_block, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(chain_id) DO UPDATE SET
                    last_block = excluded.last_block,
                    updated_at = excluded.updated_at
                """,
                (self.chain_id, block.number, now),
            )
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

        self._trim_window()
        return True

    def _trim_window(self) -> None:
        """Keep the blocks table bounded relative to the cursor.

        Everything within ``retain_blocks`` of the cursor is kept; older rows are
        deleted so a long-running scan does not grow without limit. When
        ``retain_blocks`` is 0 nothing is pruned.
        """
        if self.retain_blocks <= 0:
            return
        last = self.get_last_block()
        if last is None:
            return
        self._conn.execute(
            "DELETE FROM blocks WHERE chain_id = ? AND block_number < ?",
            (self.chain_id, last - self.retain_blocks),
        )

    def rollback_to(self, block_number: int) -> int:
        """Delete blocks above ``block_number`` and move the cursor back.

        Used by reorg recovery. Returns the number of rows deleted. Runs in a
        single transaction so the cursor can never disagree with the rows.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cursor = self._conn.execute(
                "DELETE FROM blocks WHERE chain_id = ? AND block_number > ?",
                (self.chain_id, block_number),
            )
            deleted = cursor.rowcount
            self._conn.execute(
                "UPDATE scan_state SET last_block = ?, updated_at = ? WHERE chain_id = ?",
                (block_number, _utc_now_iso(), self.chain_id),
            )
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise
        return max(deleted, 0)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
class BlockScanner:
    """Scan confirmed blocks forward from a durable cursor.

    Example
    -------
    >>> scanner = BlockScanner(client, store, config=ScannerConfig(confirmations=12))
    >>> result = scanner.scan_once()
    >>> print(result.blocks_scanned, result.last_block)
    """

    def __init__(
        self,
        client: RpcClient,
        store: StateStore,
        config: ScannerConfig | None = None,
    ) -> None:
        self.client = client
        self.store = store
        self.config = config or ScannerConfig()
        self.store.retain_blocks = self.config.reorg_window

    # -- chain identity ----------------------------------------------------
    def verify_chain_id(self, expected_chain_id: int) -> int:
        """Confirm the node serves the chain we think it does.

        A mismatch means the RPC URL points at the wrong network (a very common
        copy-paste error) and continuing would mix chains in one database.
        """
        actual = self.client.get_chain_id()
        if actual != expected_chain_id:
            raise ScannerError(
                f"chain id mismatch: node reports {actual}, "
                f"EXPECTED_CHAIN_ID is {expected_chain_id}"
            )
        return actual

    def head(self) -> int:
        return self.client.get_block_number()

    def safe_head(self, head: int | None = None) -> int:
        """Highest block we are willing to treat as final."""
        resolved = self.head() if head is None else head
        return resolved - self.config.confirmations

    # -- start position ----------------------------------------------------
    def initial_start_block(self, safe_head: int) -> int:
        """Block to start from when no cursor exists yet."""
        if self.config.start_block is not None:
            return max(0, self.config.start_block)
        return max(0, safe_head - self.config.start_block_lookback)

    def next_block(self, safe_head: int) -> int | None:
        """Block the scanner should read next, or None if caught up."""
        cursor = self.store.get_last_block()
        start = self.initial_start_block(safe_head) if cursor is None else cursor + 1
        return start if start <= safe_head else None

    # -- reorg detection ---------------------------------------------------
    def _detect_reorg(self, block: NormalizedBlock) -> int | None:
        """Compare ``block`` against locally stored state.

        Returns the block number of the common ancestor if a reorg was found
        (``0`` meaning "rescan from the start of our window"), or None if the
        chain continues cleanly from what we have stored.
        """
        previous = self.store.get_block(block.number - 1)
        if previous is None:
            # No stored predecessor: either the very first block we scan, or the
            # predecessor was pruned. Nothing to contradict, nothing to verify.
            return None

        if previous.block_hash == block.parent_hash:
            return None

        # Parent hash mismatch: the node's chain and our stored chain diverged.
        log.warning(
            "reorg_detected",
            chain_id=self.store.chain_id,
            block_number=block.number,
            expected_parent=previous.parent_hash,
            stored_parent_hash=previous.block_hash,
            received_parent_hash=block.parent_hash,
        )

        # Walk backwards through stored blocks looking for the last block whose
        # hash the node still agrees with. The node is the only source of truth
        # we have, so we re-fetch each candidate's parent chain by checking the
        # block at that height.
        window = self.store.recent_hashes(self.config.reorg_window)
        if not window:
            raise ReorgOutOfWindowError(
                f"reorg at block {block.number} but no stored blocks in window "
                f"({self.config.reorg_window}) to search for a common ancestor"
            )

        for stored in reversed(window):
            if stored.block_number >= block.number:
                continue
            current = self.client.get_block(stored.block_number)
            if current.hash == stored.block_hash:
                log.info(
                    "reorg_common_ancestor",
                    chain_id=self.store.chain_id,
                    ancestor=stored.block_number,
                    depth=block.number - stored.block_number - 1,
                )
                return stored.block_number

        raise ReorgOutOfWindowError(
            f"reorg at block {block.number}: no common ancestor found within "
            f"reorg_window={self.config.reorg_window}; stored blocks "
            f"{window[0].block_number}..{window[-1].block_number} all disagree "
            f"with the node. Refusing to guess — manual review required."
        )

    def _validate_parent_link(self, block: NormalizedBlock) -> None:
        """Internal consistency: a reorg candidate must still link internally.

        Guards against a node returning a block whose own parent chain is
        nonsense, which would otherwise be persisted as authoritative.
        """
        previous = self.store.get_block(block.number - 1)
        if previous is not None and previous.block_hash != block.parent_hash:
            raise ParentHashMismatchError(
                f"block {block.number} parent_hash {block.parent_hash} does not "
                f"match stored block {previous.block_number} hash {previous.block_hash}"
            )

    # -- main loop ---------------------------------------------------------
    def scan_once(self, head: int | None = None) -> ScanResult:
        """Scan at most ``block_batch_size`` blocks. Safe to call repeatedly.

        Returns a :class:`ScanResult`. Never skips a block because of an RPC
        failure: if a fetch fails, the exception propagates and the cursor stays
        where it was, so the block is retried on the next call.
        """
        started = time.monotonic()
        resolved_head = self.head() if head is None else head
        safe = self.safe_head(resolved_head)

        start = self.next_block(safe)
        if start is None:
            log.debug(
                "scan_caught_up",
                chain_id=self.store.chain_id,
                cursor=self.store.get_last_block(),
                safe_head=safe,
            )
            return ScanResult(
                blocks_scanned=0,
                first_block=None,
                last_block=None,
                head=resolved_head,
                safe_head=safe,
                caught_up=True,
            )

        end = min(start + self.config.block_batch_size - 1, safe)
        scanned = 0
        first: int | None = None
        last: int | None = None
        rollback_to: int | None = None

        number = start
        while number <= end:
            block = self.client.get_block(number)

            ancestor = self._detect_reorg(block)
            if ancestor is not None:
                deleted = self.store.rollback_to(ancestor)
                rollback_to = ancestor
                log.warning(
                    "reorg_rollback",
                    chain_id=self.store.chain_id,
                    ancestor=ancestor,
                    rows_deleted=deleted,
                )
                # Rewind the loop to the block right after the common ancestor.
                # Simply skipping ahead (the old behaviour) left a hole between
                # the ancestor and the block where the fork was noticed, e.g.
                # ancestor=39 and a mismatch first seen at 44 would never fetch
                # 40..43 again.
                number = ancestor + 1
                if number > end:
                    # The fork was found at the very edge of this batch; the
                    # rest is rescanned by the next call, starting from the
                    # (now rewound) cursor.
                    break
                continue

            self._validate_parent_link(block)
            inserted = self.store.commit_block(block)
            scanned += 1
            if first is None:
                first = block.number
            last = block.number

            log.info(
                "block_scanned",
                chain_id=self.store.chain_id,
                block_number=block.number,
                block_hash=block.hash,
                tx_count=len(block.transactions),
                is_new=inserted,
            )
            number += 1

        duration_ms = round((time.monotonic() - started) * 1000)
        log.info(
            "scan_batch_complete",
            chain_id=self.store.chain_id,
            blocks_scanned=scanned,
            first_block=first,
            last_block=last,
            safe_head=safe,
            duration_ms=duration_ms,
        )

        return ScanResult(
            blocks_scanned=scanned,
            first_block=first,
            last_block=last,
            head=resolved_head,
            safe_head=safe,
            reorg_rollback_to=rollback_to,
            caught_up=last is None or last >= safe,
        )

    def scan_to_head(self, max_batches: int = 1000) -> list[ScanResult]:
        """Repeatedly call :meth:`scan_once` until caught up or a batch limit."""
        results: list[ScanResult] = []
        for _ in range(max_batches):
            result = self.scan_once()
            results.append(result)
            if result.caught_up:
                break
        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _row_to_block(row: sqlite3.Row) -> StoredBlock:
    return StoredBlock(
        chain_id=int(row["chain_id"]),
        block_number=int(row["block_number"]),
        block_hash=str(row["block_hash"]),
        parent_hash=str(row["parent_hash"]),
        timestamp=int(row["timestamp"]),
        tx_count=int(row["tx_count"]),
        scanned_at=str(row["scanned_at"]),
    )


def block_to_json(block: NormalizedBlock) -> str:
    """Serialise a block for downstream consumers (JSON Lines)."""
    return json.dumps(
        {
            "number": block.number,
            "hash": block.hash,
            "parent_hash": block.parent_hash,
            "timestamp": block.timestamp,
            "tx_count": len(block.transactions),
        },
        separators=(",", ":"),
    )


def block_from_dict(data: dict[str, Any]) -> NormalizedBlock:
    """Rebuild a NormalizedBlock from a raw RPC dict. Test/helper convenience."""
    from .rpc_client import normalize_block

    return normalize_block(data)
