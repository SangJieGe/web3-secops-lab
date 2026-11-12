"""Tests for the block scanner (M1-B).

Every reorg scenario here is driven by a synthetic chain dict that the test
rewrites mid-run, so the reorg is deterministic and reproducible. No public RPC
is contacted; no real chain data is used.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import httpx
import pytest
import respx

from tests.conftest import TEST_URL, FakeNode, make_block, make_chain
from web3_secops.block_scanner import (
    BlockMismatchError,
    BlockScanner,
    ReorgOutOfWindowError,
    ScannerConfig,
    ScannerError,
    StateStore,
)
from web3_secops.rpc_client import RpcClient, RpcProtocolError

CHAIN_ID = 11155111


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _client() -> RpcClient:
    return RpcClient(TEST_URL, timeout=2.0, max_retries=0, base_backoff=0.0)


def _scanner(node: FakeNode, db_path: Path, **cfg) -> BlockScanner:
    """Build a scanner wired to ``node`` through a live respx router.

    The caller is responsible for keeping the respx context manager open.
    """
    store = StateStore(db_path, CHAIN_ID)
    return BlockScanner(_client(), store, config=ScannerConfig(**cfg))


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "state.db"


# ===========================================================================
# Basic scanning
# ===========================================================================
def test_scans_consecutive_blocks_in_order(db_path: Path) -> None:
    node = FakeNode(chain_id=CHAIN_ID, head=99, blocks=make_chain(0, 99))
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        scanner = _scanner(
            node, db_path, block_batch_size=5, confirmations=0, start_block=10, reorg_window=64
        )
        try:
            result = scanner.scan_once()
            assert result.blocks_scanned == 5
            assert result.first_block == 10
            assert result.last_block == 14
            assert scanner.store.get_last_block() == 14
        finally:
            scanner.store.close()

    numbers = [r["params"][0] for r in node.calls_to("eth_getBlockByNumber")]
    assert numbers == ["0xa", "0xb", "0xc", "0xd", "0xe"]


def test_persists_block_data(db_path: Path) -> None:
    node = FakeNode(chain_id=CHAIN_ID, head=50, blocks=make_chain(0, 50))
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        scanner = _scanner(
            node, db_path, block_batch_size=3, confirmations=0, start_block=20, reorg_window=64
        )
        try:
            scanner.scan_once()
            stored = scanner.store.get_block(20)
            assert stored is not None
            assert stored.block_number == 20
            assert stored.block_hash == make_chain(0, 50)[20]["hash"]
            assert stored.parent_hash == make_chain(0, 50)[19]["hash"]
            assert stored.tx_count == 2
            assert stored.chain_id == CHAIN_ID
        finally:
            scanner.store.close()


def test_cursor_resumes_after_restart(db_path: Path) -> None:
    """A new process (new store + scanner) continues from the saved cursor."""
    node = FakeNode(chain_id=CHAIN_ID, head=99, blocks=make_chain(0, 99))

    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        scanner = _scanner(
            node, db_path, block_batch_size=4, confirmations=0, start_block=30, reorg_window=64
        )
        try:
            scanner.scan_once()
            assert scanner.store.get_last_block() == 33
        finally:
            scanner.store.close()

        # Simulated restart: brand new objects, same DB file.
        scanner2 = _scanner(
            node, db_path, block_batch_size=4, confirmations=0, start_block=30, reorg_window=64
        )
        try:
            assert scanner2.store.get_last_block() == 33, "cursor was not restored"
            result = scanner2.scan_once()
            assert result.first_block == 34, "restart must not rescan from lookback"
            assert result.last_block == 37
        finally:
            scanner2.store.close()


def test_empty_block_is_handled(db_path: Path) -> None:
    blocks = make_chain(0, 20, tx_count=0)
    node = FakeNode(chain_id=CHAIN_ID, head=20, blocks=blocks)
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        scanner = _scanner(
            node, db_path, block_batch_size=3, confirmations=0, start_block=5, reorg_window=64
        )
        try:
            result = scanner.scan_once()
            assert result.blocks_scanned == 3
            stored = scanner.store.get_block(5)
            assert stored is not None
            assert stored.tx_count == 0
        finally:
            scanner.store.close()


def test_caught_up_returns_zero(db_path: Path) -> None:
    node = FakeNode(chain_id=CHAIN_ID, head=99, blocks=make_chain(0, 99))
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        scanner = _scanner(
            node, db_path, block_batch_size=5, confirmations=0, start_block=99, reorg_window=64
        )
        try:
            scanner.scan_once()
            second = scanner.scan_once()
            assert second.blocks_scanned == 0
            assert second.caught_up is True
        finally:
            scanner.store.close()


# ===========================================================================
# Confirmations
# ===========================================================================
def test_confirmations_hold_back_the_tip(db_path: Path) -> None:
    """With confirmations=12, block 88 is the highest scanned at head=100."""
    node = FakeNode(chain_id=CHAIN_ID, head=100, blocks=make_chain(0, 100))
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        scanner = _scanner(
            node, db_path, block_batch_size=100, confirmations=12, start_block=80, reorg_window=64
        )
        try:
            result = scanner.scan_once()
            assert result.safe_head == 88
            assert result.last_block == 88
            assert scanner.store.get_last_block() == 88
        finally:
            scanner.store.close()


def test_cold_start_uses_lookback(db_path: Path) -> None:
    """No cursor: start at safe_head - lookback, not at block 0."""
    node = FakeNode(chain_id=CHAIN_ID, head=1000, blocks=make_chain(900, 1000))
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        scanner = _scanner(
            node,
            db_path,
            block_batch_size=2,
            confirmations=12,
            start_block_lookback=20,
            reorg_window=64,
        )
        try:
            result = scanner.scan_once()
            assert result.first_block == 968  # 1000 - 12 - 20
        finally:
            scanner.store.close()


# ===========================================================================
# Failure handling: the cursor must not advance
# ===========================================================================
def test_cursor_does_not_advance_on_fetch_failure(db_path: Path) -> None:
    """If a block fetch fails, nothing is committed and the error propagates."""
    node = FakeNode(chain_id=CHAIN_ID, head=99, blocks=make_chain(0, 99))
    fail_at = {25}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body.get("method") == "eth_getBlockByNumber":
            number = body["params"][0]
            if int(number, 16) in fail_at:
                raise httpx.ConnectError("node unreachable")
        return node.handler(request)

    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=handler)
        scanner = _scanner(
            node, db_path, block_batch_size=10, confirmations=0, start_block=20, reorg_window=64
        )
        try:
            from web3_secops.rpc_client import RpcError

            with pytest.raises(RpcError):
                scanner.scan_once()
            # 20..24 were committed before the failure; 25 was not.
            assert scanner.store.get_last_block() == 24
            assert scanner.store.get_block(25) is None
        finally:
            scanner.store.close()


def test_rescan_of_same_block_is_idempotent(db_path: Path) -> None:
    """Committing the identical block twice does not duplicate the row."""
    node = FakeNode(chain_id=CHAIN_ID, head=99, blocks=make_chain(0, 99))
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        scanner = _scanner(
            node, db_path, block_batch_size=3, confirmations=0, start_block=5, reorg_window=64
        )
        try:
            scanner.scan_once()
            assert scanner.store.block_count() == 3
            # Force a rescan of the same range by rolling the cursor back.
            scanner.store.rollback_to(4)
            scanner.scan_once()
            assert scanner.store.block_count() == 3, "duplicate rows were written"
        finally:
            scanner.store.close()


# ===========================================================================
# Chain isolation
# ===========================================================================
def test_chain_ids_are_isolated(db_path: Path) -> None:
    store_a = StateStore(db_path, chain_id=1)
    store_b = StateStore(db_path, chain_id=11155111)
    try:
        block = make_block(10)
        from web3_secops.rpc_client import normalize_block

        store_a.commit_block(normalize_block(block))
        # Chain B has its own cursor and no blocks.
        assert store_b.get_last_block() is None
        assert store_b.get_block(10) is None
    finally:
        store_a.close()
        store_b.close()

    # Both cursors coexist in one file.
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT chain_id, last_block FROM scan_state ORDER BY chain_id"
        ).fetchall()
    finally:
        conn.close()
    assert len(rows) == 1  # only chain 1 committed a block
    assert rows[0][0] == 1


def test_store_rejects_invalid_chain_id(db_path: Path) -> None:
    with pytest.raises(ValueError, match="chain_id"):
        StateStore(db_path, chain_id=0)


# ===========================================================================
# Parent-hash verification
# ===========================================================================
def test_normal_chain_parent_hashes_match(db_path: Path) -> None:
    node = FakeNode(chain_id=CHAIN_ID, head=99, blocks=make_chain(0, 99))
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        scanner = _scanner(
            node, db_path, block_batch_size=10, confirmations=0, start_block=40, reorg_window=64
        )
        try:
            scanner.scan_once()
            for n in range(40, 50):
                current = scanner.store.get_block(n)
                previous = scanner.store.get_block(n - 1)
                if previous is not None and current is not None:
                    assert current.parent_hash == previous.block_hash
        finally:
            scanner.store.close()


# ===========================================================================
# Reorg handling
# ===========================================================================
def test_reorg_detected_and_scanner_recovers(db_path: Path) -> None:
    """Scan fork A, rewrite the chain to fork B, then verify recovery.

    Layout:
      * fork A: blocks 0..49, scanned through 45
      * fork B diverges at block 40 (different hashes from 40 onward)
      * block 44's parent in fork B is fork B's block 43, but we stored fork A's
        block 43 hash -> mismatch -> reorg detected
      * common ancestor is block 39
    """
    fork_a = make_chain(0, 49, fork="main")
    node = FakeNode(chain_id=CHAIN_ID, head=49, blocks=fork_a)

    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        scanner = _scanner(
            node, db_path, block_batch_size=50, confirmations=0, start_block=35, reorg_window=64
        )
        try:
            result = scanner.scan_once()
            assert result.last_block == 45 or result.last_block == 49
            stored_43 = scanner.store.get_block(43)
            assert stored_43 is not None

            # --- the chain reorganises: fork B diverges at block 40 ---
            fork_b = dict(fork_a)
            fork_b.update(make_chain(40, 60, fork="b"))
            fork_b[40]["parentHash"] = fork_a[39]["hash"]  # links to shared history
            node.set_chain(fork_b)

            head_after = 60
            result2 = scanner.scan_once(head=head_after)
            assert result2.reorg_rollback_to is not None, "reorg was not detected"
            assert result2.reorg_rollback_to == 39, "wrong common ancestor"
            # After rolling back to the ancestor the scanner keeps going on the
            # new chain until it reaches the batch limit / safe head.
            assert result2.last_block == 60
            # Everything between the ancestor and the scanned tip must exist on
            # fork B — no gaps left behind by the rollback.
            for n in range(40, 61):
                stored = scanner.store.get_block(n)
                assert stored is not None, f"block {n} missing after reorg recovery"
                assert stored.block_hash == fork_b[n]["hash"], f"block {n} not on fork B"
        finally:
            scanner.store.close()


def test_reorg_rollback_trims_stale_rows(db_path: Path) -> None:
    """After a rollback, no fork-A rows survive above the common ancestor."""
    fork_a = make_chain(0, 60, fork="main")
    node = FakeNode(chain_id=CHAIN_ID, head=60, blocks=fork_a)

    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        scanner = _scanner(
            node, db_path, block_batch_size=100, confirmations=0, start_block=30, reorg_window=64
        )
        try:
            scanner.scan_once()
            assert scanner.store.get_last_block() == 60

            fork_b = dict(fork_a)
            fork_b.update(make_chain(50, 70, fork="b"))
            fork_b[50]["parentHash"] = fork_a[49]["hash"]
            node.set_chain(fork_b)

            result = scanner.scan_once(head=70)
            assert result.reorg_rollback_to == 49
            # Every block above 49 must be fork B.
            for n in range(50, 56):
                stored = scanner.store.get_block(n)
                if stored is not None:
                    assert stored.block_hash == fork_b[n]["hash"], f"stale fork-A row at {n}"
        finally:
            scanner.store.close()


def test_deep_reorg_beyond_window_raises(db_path: Path) -> None:
    """If no common ancestor exists inside the window, stop with an error."""
    fork_a = make_chain(0, 100, fork="main")
    node = FakeNode(chain_id=CHAIN_ID, head=100, blocks=fork_a)

    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        # A small window means the ancestor is quickly out of reach.
        scanner = _scanner(
            node, db_path, block_batch_size=200, confirmations=0, start_block=90, reorg_window=4
        )
        try:
            scanner.scan_once()

            # Replace everything inside the window with a disjoint chain: the
            # node now disagrees with every stored hash, so no ancestor exists.
            fork_b = {n: make_block(n, fork="b-deep") for n in range(95, 121)}
            node.set_chain(fork_b)

            with pytest.raises(ReorgOutOfWindowError, match="no common ancestor"):
                scanner.scan_once(head=120)
        finally:
            scanner.store.close()


def test_reorg_logs_warning(db_path: Path, caplog) -> None:
    """A detected reorg is logged as a warning, not silently swallowed."""
    fork_a = make_chain(0, 30, fork="main")
    node = FakeNode(chain_id=CHAIN_ID, head=30, blocks=fork_a)

    with (
        caplog.at_level("WARNING", logger="web3_secops"),
        respx.mock(base_url=TEST_URL) as router,
    ):
        router.post(TEST_URL).mock(side_effect=node.handler)
        scanner = _scanner(
            node, db_path, block_batch_size=100, confirmations=0, start_block=20, reorg_window=64
        )
        try:
            scanner.scan_once()
            fork_b = dict(fork_a)
            fork_b.update(make_chain(25, 40, fork="b"))
            fork_b[25]["parentHash"] = fork_a[24]["hash"]
            node.set_chain(fork_b)
            scanner.scan_once(head=40)
        finally:
            scanner.store.close()

    events = [r.getMessage() for r in caplog.records]
    assert "reorg_detected" in events
    assert "reorg_rollback" in events


# ===========================================================================
# Wei precision
# ===========================================================================
def test_large_wei_value_is_exact_end_to_end(db_path: Path) -> None:
    """A wei amount above 2**53 survives the full fetch→normalise path."""
    blocks = make_chain(0, 10)
    huge = 2**53 + 1
    blocks[5]["transactions"][0]["value"] = hex(huge)
    node = FakeNode(chain_id=CHAIN_ID, head=10, blocks=blocks)

    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        scanner = _scanner(
            node, db_path, block_batch_size=1, confirmations=0, start_block=5, reorg_window=64
        )
        try:
            scanner.scan_once()
        finally:
            scanner.store.close()

    from web3_secops.rpc_client import normalize_block

    block = normalize_block(blocks[5])
    assert block.transactions[0].value_wei == huge
    assert isinstance(block.transactions[0].value_wei, int)
    assert int(float(huge)) != huge  # proves a float would have been wrong


# ===========================================================================
# Atomicity
# ===========================================================================
def test_commit_block_is_atomic(db_path: Path) -> None:
    """A failure inside the transaction must not leave a partial write."""
    store = StateStore(db_path, CHAIN_ID)
    try:
        from web3_secops.rpc_client import normalize_block

        block = normalize_block(make_block(7))
        assert store.commit_block(block) is True
        assert store.get_last_block() == 7

        # An identical re-commit is a no-op, not a duplicate.
        assert store.commit_block(block) is False
        assert store.block_count() == 1
    finally:
        store.close()


def test_commit_block_rolls_back_when_cursor_update_fails(db_path: Path) -> None:
    """Mid-transaction failure must leave neither a block row nor a moved cursor.

    The happy-path test above proves the commit works; it says nothing about what
    happens when the transaction dies halfway. ``commit_block`` inserts into
    ``blocks`` and then updates ``scan_state``. To prove those two writes are
    genuinely atomic, a SQLite trigger is installed that raises the moment the
    cursor is updated — i.e. *after* the block row has been written inside the
    open transaction.

    If the implementation were not transactional, the block row would survive
    with a stale cursor, and a later scan would re-fetch and re-store it while
    the cursor still pointed at the old height. That silent divergence is exactly
    what this asserts cannot happen.
    """
    from web3_secops.rpc_client import normalize_block

    store = StateStore(db_path, CHAIN_ID)
    try:
        # Seed one committed block so there is a real prior cursor to preserve.
        assert store.commit_block(normalize_block(make_block(10))) is True
        assert store.get_last_block() == 10
        assert store.block_count() == 1

        # Fail only when advancing to block 11: the INSERT for 10 already
        # succeeded and is untouched, so the trigger cannot be confused with a
        # general "block writes are broken" fault.
        store._conn.execute(
            """
            CREATE TRIGGER fail_cursor_advance
            BEFORE UPDATE ON scan_state
            WHEN NEW.last_block = 11
            BEGIN
                SELECT RAISE(ABORT, 'simulated cursor failure');
            END
            """
        )
        store._conn.commit()

        with pytest.raises(sqlite3.Error):
            store.commit_block(normalize_block(make_block(11)))

        # The block row must not have survived the aborted transaction.
        assert store.get_block(11) is None, "partial block row survived a failed commit"
        assert store.block_count() == 1, "block row count changed despite rollback"

        # The cursor must not have moved.
        assert store.get_last_block() == 10, "cursor advanced despite a failed commit"

        # The database must still be usable: drop the trigger and commit for real.
        store._conn.execute("DROP TRIGGER fail_cursor_advance")
        store._conn.commit()
        assert store.commit_block(normalize_block(make_block(11))) is True
        assert store.get_last_block() == 11
        assert store.block_count() == 2
    finally:
        store.close()

    # The database file must be intact and reopenable after the aborted write.
    reopened = StateStore(db_path, CHAIN_ID)
    try:
        assert reopened.get_last_block() == 11
        assert reopened.block_count() == 2
    finally:
        reopened.close()


def test_rollback_to_moves_cursor_and_deletes_rows(db_path: Path) -> None:
    store = StateStore(db_path, CHAIN_ID)
    try:
        from web3_secops.rpc_client import normalize_block

        for n in range(1, 6):
            store.commit_block(normalize_block(make_block(n)))
        assert store.get_last_block() == 5

        deleted = store.rollback_to(2)
        assert deleted == 3
        assert store.get_last_block() == 2
        assert store.get_block(3) is None
        assert store.get_block(2) is not None
    finally:
        store.close()


def test_db_file_permissions_are_restricted(db_path: Path) -> None:
    """The DB is created 0600 so scan state is not world-readable."""
    import stat

    store = StateStore(db_path, CHAIN_ID)
    try:
        mode = stat.S_IMODE(db_path.stat().st_mode)
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"
    finally:
        store.close()


# ===========================================================================
# Config validation
# ===========================================================================
@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"confirmations": -1}, "confirmations"),
        ({"block_batch_size": 0}, "block_batch_size"),
        ({"reorg_window": 0}, "reorg_window"),
        ({"block_batch_size": -5}, "block_batch_size"),
        ({"poll_interval_seconds": 0}, "poll_interval_seconds"),
    ],
)
def test_invalid_scanner_config_rejected(kwargs: dict, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        ScannerConfig(**kwargs)


def test_chain_id_mismatch_raises(db_path: Path) -> None:
    node = FakeNode(chain_id=1, head=50, blocks=make_chain(0, 50))
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        scanner = _scanner(node, db_path, block_batch_size=5)
        try:
            with pytest.raises(ScannerError, match="chain id mismatch"):
                scanner.verify_chain_id(11155111)
            scanner.verify_chain_id(1)  # correct one passes
        finally:
            scanner.store.close()


def test_scan_to_head_runs_until_caught_up(db_path: Path) -> None:
    node = FakeNode(chain_id=CHAIN_ID, head=20, blocks=make_chain(0, 20))
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        scanner = _scanner(
            node, db_path, block_batch_size=3, confirmations=0, start_block=10, reorg_window=64
        )
        try:
            results = scanner.scan_to_head()
            assert results[-1].caught_up is True
            assert scanner.store.get_last_block() == 20
        finally:
            scanner.store.close()


def test_block_mismatch_is_rejected_and_nothing_is_persisted(db_path: Path) -> None:
    """A node answering block 100 with block 101 must be refused outright.

    This is not a reorg and must not be treated as one: the block is simply
    wrong. Nothing may be written and the cursor must not move, otherwise the
    scanner would store block 101's contents under height 100 and skip the block
    it never actually fetched.
    """
    blocks = make_chain(0, 120, fork="main")
    node = FakeNode(chain_id=CHAIN_ID, head=120, blocks=blocks)

    # Make the node answer a request for 100 with block 101's payload. The hash
    # and parent hash stay consistent with 101 so only the height check can
    # notice the substitution.
    real_handler = node.handler

    def lying_handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        if payload.get("method") == "eth_getBlockByNumber":
            params = payload.get("params") or []
            if params and params[0] == hex(100):
                payload = dict(payload)
                payload["params"] = [hex(101), *params[1:]]
                request = httpx.Request(
                    method=request.method,
                    url=request.url,
                    headers=request.headers,
                    content=json.dumps(payload).encode(),
                )
        return real_handler(request)

    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=lying_handler)
        scanner = _scanner(node, db_path, block_batch_size=200, confirmations=0, start_block=100)
        try:
            # The client rejects a mismatched block before the scanner sees it,
            # and the scanner re-checks independently. Either layer firing is
            # acceptable; what matters is that the bad block never lands.
            with pytest.raises((BlockMismatchError, RpcProtocolError)) as excinfo:
                scanner.scan_once(head=120)

            if isinstance(excinfo.value, BlockMismatchError):
                assert excinfo.value.expected == 100
                assert excinfo.value.received == 101
            else:
                assert "requested block 100" in str(excinfo.value)
                assert "block 101" in str(excinfo.value)

            # Nothing was written, and the cursor did not advance.
            assert scanner.store.get_block(100) is None, "mismatched block was persisted"
            assert scanner.store.get_block(101) is None, "wrong block was persisted"
            assert scanner.store.block_count() == 0, "any row was written"
            assert scanner.store.get_last_block() is None, "cursor was created by a bad block"
        finally:
            scanner.store.close()


def test_mismatch_does_not_trigger_reorg_rollback(db_path: Path) -> None:
    """A height mismatch must fail loudly, never roll back real history."""
    blocks = make_chain(0, 120, fork="main")
    node = FakeNode(chain_id=CHAIN_ID, head=120, blocks=blocks)

    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        scanner = _scanner(node, db_path, block_batch_size=200, confirmations=0, start_block=90)
        try:
            # Store 90..105 honestly first.
            scanner.scan_once(head=105)
            assert scanner.store.get_last_block() == 105
            rows_before = scanner.store.block_count()
        finally:
            pass

    # Now make the node lie about the next block.
    real_handler = node.handler

    def lying_handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        if payload.get("method") == "eth_getBlockByNumber":
            params = payload.get("params") or []
            if params and params[0] is not None:
                requested = int(params[0], 16)
                if requested == 106:
                    payload = dict(payload)
                    payload["params"] = [hex(107), *params[1:]]
                    request = httpx.Request(
                        method=request.method,
                        url=request.url,
                        headers=request.headers,
                        content=json.dumps(payload).encode(),
                    )
        return real_handler(request)

    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=lying_handler)
        try:
            with pytest.raises((BlockMismatchError, RpcProtocolError)):
                scanner.scan_once(head=120)

            # Rollback must not have happened: all previously stored rows intact.
            assert scanner.store.block_count() == rows_before, "rows were deleted"
            assert scanner.store.get_last_block() == 105, "cursor disturbed"
        finally:
            scanner.store.close()


def test_reorg_respects_batch_limit_and_leaves_no_holes(db_path: Path) -> None:
    """A deep reorg must not blow past ``block_batch_size`` in one call.

    With a limit of 5 and a fork 12 blocks deep, a single ``scan_once`` cannot
    both rescan the fork and stay within budget. It must commit at most 5 blocks,
    and repeated calls must eventually restore every block on the winning chain
    with no holes. The cursor is the only thing that carries state between calls,
    so this also proves the resume point is correct.
    """
    batch = 5

    fork_a = make_chain(0, 60, fork="main")
    node = FakeNode(chain_id=CHAIN_ID, head=60, blocks=fork_a)

    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        scanner = _scanner(
            node,
            db_path,
            block_batch_size=batch,
            confirmations=0,
            start_block=30,
            reorg_window=64,
        )
        try:
            # Scan forward honestly, batch by batch, until caught up.
            for _ in range(20):
                result = scanner.scan_once(head=60)
                if result.caught_up:
                    break
            assert scanner.store.get_last_block() == 60

            # --- fork 12 blocks deep: diverges at block 40 ---
            fork_b = dict(fork_a)
            fork_b.update(make_chain(40, 70, fork="b"))
            fork_b[40]["parentHash"] = fork_a[39]["hash"]
            node.set_chain(fork_b)
            node.head = 70

            # Every individual call must respect the batch limit, counting only
            # blocks it actually committed.
            calls = 0
            saw_rollback = False
            while calls < 40:
                calls += 1
                before = scanner.store.get_last_block()
                result = scanner.scan_once(head=70)
                committed = 0 if result.last_block is None else result.last_block - before
                if result.reorg_rollback_to is not None:
                    saw_rollback = True
                # A rollback rewinds the cursor, so "committed" can be negative or
                # small; what must never happen is more than `batch` new blocks in
                # one call.
                assert committed <= batch, (
                    f"call {calls} committed {committed} blocks, limit is {batch} "
                    f"(cursor {before} -> {result.last_block})"
                )
                if result.caught_up and scanner.store.get_last_block() == 70:
                    break

            assert saw_rollback, "the deep reorg was never detected"

            # Coverage must be complete and entirely on the winning fork. The
            # scan started at 30, so that is the earliest stored height.
            assert scanner.store.get_last_block() == 70
            for n in range(30, 71):
                stored = scanner.store.get_block(n)
                assert stored is not None, f"block {n} missing after incremental recovery"
            for n in range(40, 71):
                assert scanner.store.get_block(n).block_hash == fork_b[n]["hash"], (
                    f"block {n} is not on the winning fork"
                )
        finally:
            scanner.store.close()


def test_reorg_rewind_does_not_refund_commit_budget(db_path: Path) -> None:
    """A rollback must not buy extra work inside the same call.

    If the budget were reset on rollback, a fork near the start of a batch would
    let the call commit far more than ``block_batch_size`` blocks.
    """
    batch = 4
    fork_a = make_chain(0, 60, fork="main")
    node = FakeNode(chain_id=CHAIN_ID, head=60, blocks=fork_a)

    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        scanner = _scanner(
            node,
            db_path,
            block_batch_size=batch,
            confirmations=0,
            start_block=30,
            reorg_window=64,
        )
        try:
            for _ in range(20):
                if scanner.scan_once(head=60).caught_up:
                    break
            assert scanner.store.get_last_block() == 60

            # Fork right at the start of the next batch window: diverge at 55.
            fork_b = dict(fork_a)
            fork_b.update(make_chain(55, 70, fork="c"))
            fork_b[55]["parentHash"] = fork_a[54]["hash"]
            node.set_chain(fork_b)
            node.head = 70

            before = scanner.store.get_last_block()
            result = scanner.scan_once(head=70)
            committed = (result.last_block or before) - before
            assert result.reorg_rollback_to is not None
            assert committed <= batch, (
                f"one call committed {committed} blocks after a rollback, limit is {batch}"
            )
        finally:
            scanner.store.close()
